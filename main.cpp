#define NOMINMAX
#include "Include.h"

static std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &w[0], sz);
    return w;
}

static std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

YR_RULES* g_compiled_rules = nullptr;
bool scanMyYara = false;
bool scanOwnYara = false;
bool scanForReplaces = false;
bool scanForDLLsOnly = false;

std::mutex cacheMutex;
std::mutex consoleMutex;
std::mutex replaceMutex;

void process_paths_worker(const std::vector<std::string>& paths, size_t start_index, size_t end_index, HANDLE hConsole) {
    for (size_t i = start_index; i < end_index; ++i) {
        const std::string& path = paths[i];
        FileInfo info;
        bool found_in_cache = false;
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = fileCache.find(path);
            if (it != fileCache.end()) {
                info = it->second;
                found_in_cache = true;
            }
        }
        if (!found_in_cache) {
            info.exists = file_exists(path);
            if (info.exists) {
                info.isDirectory = is_directory(path);
                info.isValidMZ = !info.isDirectory && isMZFile(path);
            }
            else {
                info.isDirectory = false;
                info.isValidMZ = false;
            }
            if (info.exists && info.isValidMZ) {
                info.signatureStatus = getDigitalSignature(path);
                if (info.signatureStatus != "Signed" && (scanMyYara || scanOwnYara)) {
                    if (!iequals(path, getOwnPath())) {
                        scan_with_yara(path, info.matched_rules, g_compiled_rules);
                    }
                }
            }
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache.insert_or_assign(path, info);
            }
        }
        {
            std::lock_guard<std::mutex> lock(consoleMutex);
            if (info.exists && info.isDirectory) {
                continue;
            }
            if (info.exists && info.isValidMZ) {
                SetConsoleTextAttribute(hConsole, 2);
                std::cout << "File is present    ";
                if (info.signatureStatus == "Signed") {
                    SetConsoleTextAttribute(hConsole, 2);
                    std::cout << info.signatureStatus << "        ";
                }
                else if (info.signatureStatus == "Not signed") {
                    SetConsoleTextAttribute(hConsole, 4);
                    std::cout << info.signatureStatus << "    ";
                }
                else {
                    SetConsoleTextAttribute(hConsole, 4);
                    std::cout << info.signatureStatus << "  ";
                }
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                std::cout << "    ";
                std::string filename;
                size_t pos = path.find_last_of("\\/");
                filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;
                if (scanForReplaces) {
                    std::lock_guard<std::mutex> repl(replaceMutex);
                    FindReplace(filename);
                }
                if (!info.matched_rules.empty()) {
                    SetConsoleTextAttribute(hConsole, 4);
                    for (auto& rule_name : info.matched_rules) {
                        std::cout << "[" << rule_name << "]";
                    }
                    SetConsoleTextAttribute(hConsole, 7);
                }
                std::cout << "\n";
            }
            else if (info.exists && !info.isValidMZ) {
                SetConsoleTextAttribute(hConsole, 2);
                std::cout << "File is present    ";
                SetConsoleTextAttribute(hConsole, 6);
                std::cout << "Not MZ        ";
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                std::cout << "\n";
            }
            else if (!info.exists) {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << "File is deleted    deleted       ";
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                std::cout << "\n";
            }
        }
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("PathsParser tool, made by espouken");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!privilege("SeDebugPrivilege")) {
        std::cout << "Press Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    std::string input;
    std::cout << "Do you want to scan for my yara rules? (Y/N): ";
    std::getline(std::cin, input);
    scanMyYara = (input == "Y" || input == "y");

    std::cout << "Do you want to scan your own yara rules? (Y/N): ";
    std::getline(std::cin, input);
    scanOwnYara = (input == "Y" || input == "y");

    std::cout << "Do you want to scan for replaces? (Y/N): ";
    std::getline(std::cin, input);
    scanForReplaces = (input == "Y" || input == "y");

    std::cout << "Do you want to scan for DLLs only? (Y/N): ";
    std::getline(std::cin, input);
    scanForDLLsOnly = (input == "Y" || input == "y");

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA.\nPress Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    if (scanMyYara)       initializeGenericRules();
    if (scanOwnYara)      initializateCustomRules();

    if (scanMyYara || scanOwnYara) {
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);
        yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);
        for (auto& r : genericRules)
            yr_compiler_add_string(compiler, r.rule.c_str(), r.name.c_str());
        yr_compiler_get_rules(compiler, &g_compiled_rules);
        yr_compiler_destroy(compiler);
    }

    if (scanForReplaces) {
        initReplaceParser();
        PreProcessReplacements(replaceParserDir + "\\replaces.txt");
    }

    auto paths = getAllTargetPaths();
    if (paths.empty()) {
        SetConsoleTextAttribute(hConsole, 4);
        std::cout << "No valid paths found.\n";
        SetConsoleTextAttribute(hConsole, 7);
        if (g_compiled_rules) yr_rules_destroy(g_compiled_rules);
        yr_finalize();
        std::cout << "Press Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    unsigned th = std::thread::hardware_concurrency();
    unsigned num_threads = th > 0 ? th : 1;
    size_t total = paths.size();
    size_t per = (total + num_threads - 1) / num_threads;

    std::vector<std::thread> workers;
    size_t idx = 0;
    std::cout << "Starting processing " << total << " paths with " << num_threads << " threads...\n";
    for (unsigned t = 0; t < num_threads && idx < total; ++t) {
        size_t end = std::min(idx + per, total);
        workers.emplace_back(process_paths_worker, std::cref(paths), idx, end, hConsole);
        idx = end;
    }
    for (auto& w : workers) if (w.joinable()) w.join();

    std::cout << "Processing finished.\n";

    if (scanForReplaces) {
        DestroyReplaceParser();
        WriteAllReplacementsToFileAndPrintSummary();
    }

    if (g_compiled_rules) {
        yr_rules_destroy(g_compiled_rules);
        g_compiled_rules = nullptr;
    }
    yr_finalize();

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "------End------\n";
    std::cin.get();
    return 0;
}

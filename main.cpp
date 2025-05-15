#define NOMINMAX
#include "Include.h"

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
                std::cout << path << "    ";

                std::string filename;
                size_t pos = path.find_last_of("\\/");
                if (pos != std::string::npos) {
                    filename = path.substr(pos + 1);
                }
                else {
                    filename = path;
                }

                if (scanForReplaces) {
                    std::lock_guard<std::mutex> replaceLock(replaceMutex);
                    FindReplace(filename);
                }

                if (!info.matched_rules.empty()) {
                    SetConsoleTextAttribute(hConsole, 4);
                    for (const auto& rule_name : info.matched_rules) {
                        std::cout << "[" << rule_name << "]";
                    }
                    SetConsoleTextAttribute(hConsole, 7);
                }
                std::cout << std::endl;
            }
            else if (info.exists && !info.isValidMZ) {
                SetConsoleTextAttribute(hConsole, 2);
                std::cout << "File is present    ";
                SetConsoleTextAttribute(hConsole, 6);
                std::cout << "Not MZ        ";
                SetConsoleTextAttribute(hConsole, 7);
                std::cout << path << std::endl;
            }
            else if (!info.exists) {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << "File is deleted    deleted       ";
                SetConsoleTextAttribute(hConsole, 7);
                std::cout << path << std::endl;
            }
        }
    }
}

int main() {
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

    std::cout << "Do you want to scan your own yara rules? (Y/N) (read repo's readme to learn how to use it): ";
    std::getline(std::cin, input);
    scanOwnYara = (input == "Y" || input == "y");

    std::cout << "Do you want to scan for replaces? (Y/N): ";
    std::getline(std::cin, input);
    scanForReplaces = (input == "Y" || input == "y");

    std::cout << "Do you want to scan for DLLs only? (Y/N): ";
    std::getline(std::cin, input);
    scanForDLLsOnly = (input == "Y" || input == "y");

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA." << std::endl;

        std::cout << "Press Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    if (scanMyYara) {
        initializeGenericRules();
    }
    if (scanOwnYara) {
        initializateCustomRules();
    }

    if (scanMyYara || scanOwnYara) {
        YR_COMPILER* compiler = NULL;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
            std::cerr << "Failed to create YARA compiler." << std::endl;
            yr_finalize();
            std::cout << "Press Enter to exit...";
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cin.get();
            return 1;
        }

        yr_compiler_set_callback(compiler, compiler_error_callback, NULL);

        for (const auto& rule_entry : genericRules) {

            if (yr_compiler_add_string(compiler, rule_entry.rule.c_str(), rule_entry.name.c_str()) == 0) {

            }
            else {
                std::cerr << "Error adding rule string to compiler: " << rule_entry.name << std::endl;

            }
        }

        if (yr_compiler_get_rules(compiler, &g_compiled_rules) != ERROR_SUCCESS) {
            std::cerr << "Failed to get compiled YARA rules." << std::endl;
            yr_compiler_destroy(compiler);
            yr_finalize();
            std::cout << "Press Enter to exit...";
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cin.get();
            return 1;
        }
        yr_compiler_destroy(compiler);

    }

    if (scanForReplaces) {
        initReplaceParser();
        PreProcessReplacements(replaceParserDir + "\\replaces.txt");
    }

    std::vector<std::string> paths = getAllTargetPaths();

    if (paths.empty()) {
        SetConsoleTextAttribute(hConsole, 4);
        std::cout << "       No valid paths found in any of the target files." << std::endl;
        std::cout << "       Make sure you follow the readme instructions in order to make it work." << std::endl;
        SetConsoleTextAttribute(hConsole, 7);

        if (g_compiled_rules) yr_rules_destroy(g_compiled_rules);
        yr_finalize();
        std::cout << "Press Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    const unsigned int num_threads_hint = std::thread::hardware_concurrency();
    const unsigned int num_threads = num_threads_hint > 0 ? num_threads_hint : 1;
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    size_t total_paths = paths.size();

    size_t paths_per_thread = (total_paths > 0) ? static_cast<size_t>(std::ceil(static_cast<double>(total_paths) / num_threads)) : 0;
    if (paths_per_thread == 0 && total_paths > 0) paths_per_thread = 1;

    std::cout << "Starting processing " << total_paths << " paths with " << num_threads << " threads..." << std::endl;
    size_t start_index = 0;
    for (unsigned int i = 0; i < num_threads && start_index < total_paths; ++i) {
        size_t end_index = std::min(start_index + paths_per_thread, total_paths);
        if (start_index < end_index) {
            threads.emplace_back(process_paths_worker, std::ref(paths), start_index, end_index, hConsole);
        }
        start_index = end_index;
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "Processing finished." << std::endl;

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
    std::cout << "------End------" << std::endl;
    std::cin.clear();
    std::cin.sync();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return 0;
}

#define NOMINMAX
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <sstream>

// Link with Wintrust.lib
#pragma comment(lib, "wintrust")

// Include YARA headers
extern "C" {
#include <yara.h>
}

// === Helper UTF8 <-> wstring
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

// === FileInfo struct holds info about a file
struct FileInfo {
    bool exists = false;
    bool isDirectory = false;
    bool isValidMZ = false;
    std::string signatureStatus;
    std::vector<std::string> matched_rules;  // for yara matched rules
};

// Cache & mutexes
std::unordered_map<std::string, FileInfo> fileCache;
std::mutex cacheMutex;
std::mutex consoleMutex;

// === Checks
bool file_exists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES);
}
bool is_directory(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
}
bool is_mz_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char mz[2];
    f.read(mz, 2);
    return mz[0] == 'M' && mz[1] == 'Z';
}

// WinVerifyTrust check for digital signature
std::string getDigitalSignature(const std::string& filePath) {
    LONG status;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileData = {0};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    std::wstring wpath = utf8_to_wstring(filePath);
    fileData.pcwszFilePath = wpath.c_str();
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = {0};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = 0;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    winTrustData.dwUIContext = 0;

    status = WinVerifyTrust(nullptr, &WVTPolicyGUID, &winTrustData);

    switch (status) {
        case ERROR_SUCCESS:
            return "Signed";
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_SUBJECT_NOT_TRUSTED:
        case TRUST_E_PROVIDER_UNKNOWN:
        case TRUST_E_ACTION_UNKNOWN:
        case TRUST_E_CERT_SIGNATURE:
            return "Not signed";
        default:
            {
                std::stringstream ss;
                ss << "Error code 0x" << std::hex << status;
                return ss.str();
            }
    }
}

// Placeholder YARA related functions (implement or link your real code)
YR_RULES* g_compiled_rules = nullptr;

void initializeGenericRules() {
    // TODO: Initialize generic YARA rules here
    // e.g. compile yara rules from string or files
}

void initializeCustomRules() {
    // TODO: Initialize user custom YARA rules here
}

void scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules, YR_RULES* compiled_rules) {
    // TODO: Implement your yara scanning here
    // On match, push matched rule names into matched_rules vector

    // For demonstration only:
    // matched_rules.push_back("dummy_rule");
}

// Helper to filter DLLs only if needed
bool is_dll(const std::string& path) {
    auto dot = path.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == "dll";
}

// Worker thread function
void process_paths_worker(
    const std::vector<std::string>& paths,
    size_t start_index,
    size_t end_index,
    HANDLE hConsole,
    bool scanMyYara,
    bool scanOwnYara,
    bool scanForDLLsOnly)
{
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
                info.isValidMZ = !info.isDirectory && is_mz_file(path);
            }
            else {
                info.isDirectory = false;
                info.isValidMZ = false;
            }

            if (info.exists && info.isValidMZ) {
                info.signatureStatus = getDigitalSignature(path);

                if ((scanMyYara || scanOwnYara) && (!scanForDLLsOnly || (scanForDLLsOnly && is_dll(path)))) {
                    scan_with_yara(path, info.matched_rules, g_compiled_rules);
                }
            }

            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache[path] = info;
            }
        }

        {
            std::lock_guard<std::mutex> lock(consoleMutex);

            if (info.exists && info.isDirectory) {
                continue; // skip directories
            }

            if (info.exists && info.isValidMZ) {
                SetConsoleTextAttribute(hConsole, 2); // green
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

// Function to collect all files in target paths (simulate getAllTargetPaths)
std::vector<std::string> getAllTargetPaths(const std::vector<std::string>& targets, bool scanForDLLsOnly) {
    std::vector<std::string> result;
    for (const auto& target : targets) {
        WIN32_FIND_DATAA findFileData;
        std::string searchPath = target + "\\*";
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) continue;
            std::string fullPath = target + "\\" + findFileData.cFileName;

            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Recursively get files
                auto subPaths = getAllTargetPaths({fullPath}, scanForDLLsOnly);
                result.insert(result.end(), subPaths.begin(), subPaths.end());
            }
            else {
                if (scanForDLLsOnly) {
                    if (is_dll(fullPath)) {
                        result.push_back(fullPath);
                    }
                }
                else {
                    result.push_back(fullPath);
                }
            }
        } while (FindNextFileA(hFind, &findFileData) != 0);

        FindClose(hFind);
    }
    return result;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("PathsParser tool, C++ port");

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // === Ask user options
    std::string input;
    bool scanMyYara = false;
    bool scanOwnYara = false;
    bool scanForReplaces = false; // placeholder, you can add real code later
    bool scanForDLLsOnly = false;

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

    // Initialize YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA.\nPress Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    if (scanMyYara) initializeGenericRules();
    if (scanOwnYara) initializeCustomRules();

    // Compile rules if needed
    if (scanMyYara || scanOwnYara) {
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);
        // Add your rules here to compiler (left as TODO)
        // e.g. yr_compiler_add_string(compiler, ruleString, ruleName);
        yr_compiler_get_rules(compiler, &g_compiled_rules);
        yr_compiler_destroy(compiler);
    }

    // Get scan targets - you can define your own
    std::vector<std::string> scanTargets = {
        std::string(getenv("USERPROFILE")) + "\\Downloads",
        std::string(getenv("USERPROFILE")) + "\\Documents",
        std::string(getenv("WINDIR")) + "\\SysWOW64",
        std::string(getenv("WINDIR")) + "\\System32"
    };

    std::cout << "Collecting paths to scan...\n";
    auto paths = getAllTargetPaths(scanTargets, scanForDLLsOnly);

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

    // Multithreaded scan
    unsigned th = std::thread::hardware_concurrency();
    unsigned num_threads = th > 0 ? th : 1;
    size_t total = paths.size();
    size_t per = (total + num_threads - 1) / num_threads;

    std::vector<std::thread> workers;
    size_t idx = 0;
    std::cout << "Starting processing " << total << " paths with " << num_threads << " threads...\n";

    for (unsigned t = 0; t < num_threads && idx < total; ++t) {
        size_t end = std::min(idx + per, total);
        workers.emplace_back(process_paths_worker, std::cref(paths), idx, end, hConsole, scanMyYara, scanOwnYara, scanForDLLsOnly);
        idx = end;
    }
    for (auto& w : workers) if (w.joinable()) w.join();

    std::cout << "Processing finished.\n";

    if (scanForReplaces) {
        // TODO: add your replace parser destruction & printing here
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

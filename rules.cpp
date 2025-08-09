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
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <memory>

// Link with Wintrust.lib
#pragma comment(lib, "wintrust")

extern "C" {
#include <yara.h>
}

namespace fs = std::filesystem;

// === UTF8 <-> wstring helpers
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

// === FileInfo struct
struct FileInfo {
    bool exists = false;
    bool isDirectory = false;
    bool isValidMZ = false;
    std::string signatureStatus;
    std::vector<std::string> matched_rules;
};

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
    char mz[2]{};
    f.read(mz, 2);
    return mz[0] == 'M' && mz[1] == 'Z';
}

// WinVerifyTrust signature check
std::string getDigitalSignature(const std::string& filePath) {
    LONG status;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileData = { sizeof(WINTRUST_FILE_INFO), nullptr, nullptr, nullptr };
    std::wstring wpath = utf8_to_wstring(filePath);
    fileData.pcwszFilePath = wpath.c_str();

    WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
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

// === Global compiled rules container
YR_RULES* g_compiled_rules = nullptr;

// === Compile rules container (rule name + content)
struct YaraRule {
    std::string name;
    std::string content;
};
std::vector<YaraRule> genericRules;
std::vector<YaraRule> customRules;

// === Compiler error callback
void compiler_error_callback(int error_level, const char* file_name, int line, const char* message, void* user_data) {
    std::cerr << "YARA Compiler Error [" << error_level << "] in file " << (file_name ? file_name : "(null)")
              << " line " << line << ": " << message << "\n";
}

// === Load your generic YARA rules here (example)
void initializeGenericRules() {
    // Example: Add a simple dummy rule, replace with your actual generic rules.
    const char* example_rule = 
        "rule DummyRule {\n"
        "    strings:\n"
        "        $a = \"dummy\"\n"
        "    condition:\n"
        "        $a\n"
        "}\n";
    genericRules.push_back({ "DummyRule", example_rule });
}

// === Load custom YARA rules from .yar files in your executable directory
void initializeCustomRules() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    fs::path dir = fs::path(exePath).parent_path();

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".yar") {
            std::ifstream file(entry.path());
            if (!file.is_open()) {
                std::cerr << "Failed to open custom rule file: " << entry.path().string() << "\n";
                continue;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();
            if (content.empty()) {
                std::cerr << "Empty custom rule file: " << entry.path().string() << "\n";
                continue;
            }

            // Validate the rule with a temporary compiler
            YR_COMPILER* temp_compiler = nullptr;
            if (yr_compiler_create(&temp_compiler) != ERROR_SUCCESS) {
                std::cerr << "Failed to create temporary YARA compiler\n";
                continue;
            }
            yr_compiler_set_callback(temp_compiler, compiler_error_callback, nullptr);
            int errors = yr_compiler_add_string(temp_compiler, content.c_str(), entry.path().filename().string().c_str());
            yr_compiler_destroy(temp_compiler);

            if (errors == 0) {
                customRules.push_back({ entry.path().stem().string(), content });
                std::cout << "Loaded custom rule: " << entry.path().filename().string() << "\n";
            }
            else {
                std::cerr << "Failed to compile custom rule: " << entry.path().filename().string() << "\n";
            }
        }
    }
}

// === YARA callback function for scanning
int yara_callback(int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        auto* matched_rules = (std::vector<std::string>*)user_data;
        matched_rules->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// === Scan a single file with YARA rules, returns true if matched
bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules, YR_RULES* rules) {
    matched_rules.clear();

    if (!rules)
        return false;

    std::wstring wpath = utf8_to_wstring(path);

    HANDLE hFile = CreateFileW(
        wpath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER filesize{};
    if (!GetFileSizeEx(hFile, &filesize) || filesize.QuadPart > SIZE_MAX) {
        CloseHandle(hFile);
        return false;
    }

    size_t size = static_cast<size_t>(filesize.QuadPart);
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer.get(), (DWORD)size, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (!ok || bytesRead != size)
        return false;

    int res = yr_rules_scan_mem(
        rules,
        buffer.get(),
        size,
        SCAN_FLAGS_FAST_MODE,
        yara_callback,
        &matched_rules,
        0
    );

    return !matched_rules.empty();
}

// === Check if a file is a DLL by extension
bool is_dll(const std::string& path) {
    auto dot = path.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == "dll";
}

// === Recursively collect all files from given targets, filter by DLLs if needed
std::vector<std::string> getAllTargetPaths(const std::vector<std::string>& targets, bool scanForDLLsOnly) {
    std::vector<std::string> result;
    for (const auto& target : targets) {
        if (!fs::exists(target)) continue;

        if (fs::is_regular_file(target)) {
            if (!scanForDLLsOnly || is_dll(target)) {
                result.push_back(target);
            }
        }
        else if (fs::is_directory(target)) {
            for (auto& p : fs::recursive_directory_iterator(target)) {
                if (fs::is_regular_file(p)) {
                    if (!scanForDLLsOnly || is_dll(p.path().string())) {
                        result.push_back(p.path().string());
                    }
                }
            }
        }
    }
    return result;
}

// === Worker thread scanning function
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
            if (!info.isDirectory && info.isValidMZ) {
                info.signatureStatus = getDigitalSignature(path);
            }
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache[path] = info;
            }
        }

        if (!info.exists) {
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << "File does not exist: " << path << "\n";
            continue;
        }
        if (info.isDirectory) {
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << "Skipping directory: " << path << "\n";
            continue;
        }
        if (!info.isValidMZ) {
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << "Not a valid MZ file: " << path << "\n";
            continue;
        }
        if (scanForDLLsOnly && !is_dll(path)) {
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << "Skipping non-DLL file: " << path << "\n";
            continue;
        }

        // Clear matched rules
        std::vector<std::string> matched_rules;

        // Scan with generic rules
        if (scanMyYara && g_compiled_rules != nullptr) {
            bool matched = scan_with_yara(path, matched_rules, g_compiled_rules);
            if (matched) {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << "[Generic YARA match] " << path << "\n";
                for (const auto& rule_name : matched_rules) {
                    std::cout << "  Rule: " << rule_name << "\n";
                }
            }
        }

        // Scan with custom rules
        if (scanOwnYara && !customRules.empty()) {
            // Compile custom rules on demand
            YR_COMPILER* compiler = nullptr;
            if (yr_compiler_create(&compiler) == ERROR_SUCCESS) {
                yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);
                bool compile_success = true;

                for (const auto& r : customRules) {
                    if (yr_compiler_add_string(compiler, r.content.c_str(), r.name.c_str()) != 0) {
                        compile_success = false;
                        break;
                    }
                }

                if (compile_success) {
                    YR_RULES* compiled = nullptr;
                    if (yr_compiler_get_rules(compiler, &compiled) == ERROR_SUCCESS) {
                        bool matched = scan_with_yara(path, matched_rules, compiled);
                        if (matched) {
                            std::lock_guard<std::mutex> lock(consoleMutex);
                            std::cout << "[Custom YARA match] " << path << "\n";
                            for (const auto& rule_name : matched_rules) {
                                std::cout << "  Rule: " << rule_name << "\n";
                            }
                        }
                        yr_rules_destroy(compiled);
                    }
                }
                yr_compiler_destroy(compiler);
            }
        }
    }
}

int main(int argc, char** argv) {
    // Initialize YARA library
    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA library\n";
        return 1;
    }

    initializeGenericRules();
    initializeCustomRules();

    // Compile generic rules at startup
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "Failed to create YARA compiler\n";
        yr_finalize();
        return 1;
    }
    yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);

    for (const auto& r : genericRules) {
        if (yr_compiler_add_string(compiler, r.content.c_str(), r.name.c_str()) != 0) {
            std::cerr << "Failed to add generic rule: " << r.name << "\n";
            yr_compiler_destroy(compiler);
            yr_finalize();
            return 1;
        }
    }

    if (yr_compiler_get_rules(compiler, &g_compiled_rules) != ERROR_SUCCESS) {
        std::cerr << "Failed to get compiled generic rules\n";
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }
    yr_compiler_destroy(compiler);

    // User options for scanning
    bool scanMyYara = true;       // Scan with generic rules
    bool scanOwnYara = true;      // Scan with custom rules
    bool scanForReplaces = false; // (Unused here, but keep your option)
    bool scanForDLLsOnly = false; // Scan only DLLs?

    // Collect target paths
    std::vector<std::string> targets;
    if (argc > 1) {
        for (int i = 1; i < argc; ++i)
            targets.push_back(argv[i]);
    }
    else {
        // Default to current directory scanning
        targets.push_back(".");
    }

    std::vector<std::string> paths = getAllTargetPaths(targets, scanForDLLsOnly);

    if (paths.empty()) {
        std::cout << "No files to scan.\n";
        yr_rules_destroy(g_compiled_rules);
        yr_finalize();
        return 0;
    }

    // Determine number of threads
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 2;

    size_t batch_size = paths.size() / num_threads;
    if (batch_size == 0) batch_size = paths.size();

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    std::vector<std::thread> workers;
    size_t start = 0;

    for (unsigned int i = 0; i < num_threads && start < paths.size(); ++i) {
        size_t end = std::min(start + batch_size, paths.size());
        workers.emplace_back(process_paths_worker,
            std::cref(paths),
            start,
            end,
            hConsole,
            scanMyYara,
            scanOwnYara,
            scanForDLLsOnly);
        start = end;
    }

    for (auto& t : workers) {
        if (t.joinable())
            t.join();
    }

    yr_rules_destroy(g_compiled_rules);
    yr_finalize();

    return 0;
}

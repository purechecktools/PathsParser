#include "Include.h"
#include "yara.h" 
#include <filesystem>
#include <sstream> 

namespace fs = std::filesystem;

std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {

    fprintf(stderr, "YARA Compiler ");
    switch (error_level) {
    case YARA_ERROR_LEVEL_ERROR:
        fprintf(stderr, "Error");
        break;
    case YARA_ERROR_LEVEL_WARNING:
        fprintf(stderr, "Warning");
        break;
    default:
        fprintf(stderr, "Message");
        break;
    }
    if (file_name) {
        fprintf(stderr, " in %s", file_name);
    }
    if (line_number > 0) {
        fprintf(stderr, "(%d)", line_number);
    }
    fprintf(stderr, ": %s\n", message);
}

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched_rules_ptr = static_cast<std::vector<std::string>*>(user_data);
        if (matched_rules_ptr) {
            matched_rules_ptr->push_back(rule->identifier);
        }
    }
    return CALLBACK_CONTINUE;
}

void initializeGenericRules() {

    addGenericRule("Generic A", R"(
import "pe" 

rule A
{
    strings:
        $a = /clicker/i ascii wide
        $b = /autoclick/i ascii wide
        $c = /clicking/i ascii wide
        $d = /String Cleaner/i ascii wide
        $e = /double_click/i ascii wide
        $f = /Jitter Click/i ascii wide
        $g = /Butterfly Click/i ascii wide

    condition:
        pe.is_pe and
        filesize <= 41943040 and 
        any of them
}
)");

    addGenericRule("Specifics A", R"(
import "pe" 

rule sA
{
    strings:
        $a = /Exodus\.codes/i ascii wide
        $b = /slinky\.gg/i ascii wide
        $c = /slinkyhook\.dll/i ascii wide
        $d = /slinky_library\.dll/i ascii wide
        $e = /\[!\] Failed to find Vape jar/i ascii wide
        $f = /Vape Launcher/i ascii wide
        $g = /vape\.gg/i ascii wide
        $h = /C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3\.pdb/i ascii wide
        $i = /discord\.gg\/advantages/i ascii wide
        $j = /String cleaner/i ascii wide
        $k = /Open Minecraft, then try again\./i ascii wide
        $l = /The clicker code was done by Nightbot\. I skidded it :\)/i ascii wide
        $m = /PE injector/i ascii wide
        $n = /name="SparkCrack\.exe"/i ascii wide
        $o = /starlight v1\.0/i ascii wide
        $p = /Sapphire LITE Clicker/i ascii wide
        $q = /Striker\.exe/i ascii wide
        $r = /Cracked by Kangaroo/i ascii wide
        $s = /Monolith Lite/i ascii wide
        $t = /B\.fagg0t0/i ascii wide
        $u = /B\.fag0/i ascii wide
        $v = /\.\fag1/i ascii wide
        $w = /dream-injector/i ascii wide
        $x = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external\.pdb/i ascii wide
        $y = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal\.pdb/i ascii wide
        $z = /UNICORN CLIENT/i ascii wide
        $aa = /Adding delay to Minecraft/i ascii wide
        $ab = /rightClickChk\.BackgroundImage/i ascii wide
        $ac = /UwU Client/i ascii wide
        $ad = /lithiumclient\.wtf/i ascii wide
        $ae = /breeze\.rip/i ascii wide
        $af = /breeze\.dll/i ascii wide
        $ag = /Failed injecting dll/i ascii wide
        $ah = /Breeze\.InjectScreen/i ascii wide
    condition:
        pe.is_pe and
        filesize <= 41943040 and
        any of them
}
)");

    // MORE!
}

static std::wstring utf8_to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

bool scan_with_yara(const std::string& path,
    std::vector<std::string>& matched_rules,
    YR_RULES* rules)
{
    if (!rules)
        return false;

    matched_rules.clear();
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

    LARGE_INTEGER filesize;
    if (!GetFileSizeEx(hFile, &filesize) || filesize.QuadPart > SIZE_MAX) {
        CloseHandle(hFile);
        return false;
    }

    size_t size = static_cast<size_t>(filesize.QuadPart);
    auto buffer = std::make_unique<BYTE[]>(size);

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer.get(), (DWORD)size, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (!ok || bytesRead != size)
        return false;

    // The callback used by yr_rules_scan_mem should have signature:
    // int callback(int message, void* message_data, void* user_data);
    auto yara_callback = [](int message, void* message_data, void* user_data) -> int {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            YR_RULE* rule = static_cast<YR_RULE*>(message_data);
            auto* matched_rules_ptr = static_cast<std::vector<std::string>*>(user_data);
            matched_rules_ptr->push_back(rule->identifier);
        }
        return CALLBACK_CONTINUE;
    };

    int result = yr_rules_scan_mem(
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

void initializateCustomRules() {
    std::string ownDirectory = getOwnDirectory();

    for (const auto& entry : fs::directory_iterator(ownDirectory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".yar") {
            std::string filePath = entry.path().string();

            printf("Found and processing custom rule file: %s\n", filePath.c_str());

            std::ifstream file(entry.path());
            if (!file.is_open()) {
                fprintf(stderr, "Failed to open custom rule file: %s\n", filePath.c_str());
                continue;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string ruleContent = buffer.str();

            if (ruleContent.empty()) {
                fprintf(stderr, "Custom rule file is empty: %s\n", filePath.c_str());
                continue;
            }

            YR_COMPILER* validation_compiler = nullptr;
            if (yr_compiler_create(&validation_compiler) != ERROR_SUCCESS) {
                fprintf(stderr, "Failed to create YARA compiler for validating rule file: %s\n", filePath.c_str());
                continue;
            }

            yr_compiler_set_callback(validation_compiler, compiler_error_callback, nullptr);

            int compile_errors = yr_compiler_add_string(validation_compiler, ruleContent.c_str(), entry.path().filename().string().c_str());

            yr_compiler_destroy(validation_compiler);

            if (compile_errors == 0) {

                std::string ruleName = entry.path().stem().string();
                addGenericRule(ruleName, ruleContent);
                printf("Successfully validated and queued custom rule: %s\n", ruleName.c_str());
            }
            else {
                fprintf(stderr, "Failed to compile/validate YARA rule from file: %s. Errors: %d. Rule not added.\n", filePath.c_str(), compile_errors);
            }
        }
    }
}

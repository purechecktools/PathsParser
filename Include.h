#pragma once

#include <algorithm>
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <Psapi.h>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mscat.h>
#include <fstream>
#include <wincrypt.h>
#include <unordered_map>
#include <filesystem>
#include <mutex>
#include <cmath>
#include <functional>
#include <limits>
#include <unordered_set>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

__int64 privilege(const char* priv);
std::string getDigitalSignature(const std::string& filePath);
bool file_exists(const std::string& path);
std::string getOwnPath();
bool isMZFile(const std::string& path);
std::string getOwnDirectory();
bool hasInvalidSemicolonPath(const std::string& str);
bool isValidPathToProcess(const std::string& path, bool searchfordll);
std::string extractValidPath(const std::string& line);
std::vector<std::string> readPathsFromFile(const std::string& filePath);
std::vector<std::string> getAllTargetPaths();
bool iequals(const std::string& a, const std::string& b);
bool is_directory(const std::string& path);

extern bool scanForDLLsOnly;

extern std::string replaceParserDir;
bool initReplaceParser();
bool DestroyReplaceParser();
void PreProcessReplacements(const std::string& logFilePath);
void FindReplace(const std::string& inputFileName);
void WriteAllReplacementsToFileAndPrintSummary();

struct ReplacementEntry {
    std::string fileName;
    std::string replaceType;
    std::string details;
};

extern std::unordered_map<std::string, std::vector<ReplacementEntry>> replacementCache;

struct GenericRule {
    std::string name;
    std::string rule;
};

struct YaraError {
    std::string file_name;
    int line_number;
    std::string message;
};

struct FileInfo {
    bool exists = false;
    bool isDirectory = false;
    bool isValidMZ = false;
    std::string signatureStatus;
    std::vector<std::string> matched_rules;
};


static std::unordered_map<std::string, FileInfo> fileCache;

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);

void initializateCustomRules();
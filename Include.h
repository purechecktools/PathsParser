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
#include <algorithm>
#include <thread>
#include <atomic>
#include <mscat.h>
#include <fstream>
#include <wincrypt.h>
#include <filesystem>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

__int64 privilege(const char* priv);
std::string getDigitalSignature(const std::string& filePath);
bool file_exists(const std::string& path);
std::string getOwnPath();
bool isMZFile(const std::string& path);
std::string getOwnDirectory();
bool hasInvalidSemicolonPath(const std::string& str);
bool isValidPathToProcess(const std::string& path);
std::string extractValidPath(const std::string& line);
std::vector<std::string> readPathsFromFile(const std::string& filePath);
std::vector<std::string> getAllTargetPaths();
bool iequals(const std::string& a, const std::string& b);

bool initReplaceParser();
bool DestroyReplaceParser();
void FindReplace(const std::string& inputFileName);
void WriteAllReplacementsToFileAndPrintSummary();

struct GenericRule {
    std::string name;
    std::string rule;
};

struct YaraError {
    std::string file_name;
    int line_number;
    std::string message;
};

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);
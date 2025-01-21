#include "Include.h"
#include <fstream>

int main() {
    SetConsoleTitleA("PathsParser tool, made by espouken");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!privilege("SeDebugPrivilege")) {
        return 1;
    }

    initializeGenericRules();
    initReplaceParser();

    std::vector<std::string> paths = getAllTargetPaths();

    std::cout << "\n";
    if (paths.empty()) {
        SetConsoleTextAttribute(hConsole, 4);
        std::cout << "      No valid paths found in any of the target files." << std::endl;
        std::cout << "      Make sure you follow the readme instructions in order to make it work." << std::endl;
        SetConsoleTextAttribute(hConsole, 7);
        std::cin.ignore();
        return 1;
    }


    for (const std::string& path : paths) {
        if (fileCache.find(path) == fileCache.end()) {
            FileInfo info;
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

                if (info.signatureStatus != "Signed") {
                    if (!iequals(path, getOwnPath())) {
                        std::vector<std::string> matched_rules;
                        bool yara_match = scan_with_yara(path, matched_rules);
                        if (yara_match) {
                            info.matched_rules = matched_rules;
                        }
                    }
                }
            }
            fileCache[path] = info;
        }

        const FileInfo& info = fileCache[path];

        if (info.exists && info.isDirectory) {
            continue;
        }

        if (info.exists && info.isValidMZ) {
            SetConsoleTextAttribute(hConsole, 2);
            std::cout << "File is present   ";

            if (info.signatureStatus == "Signed") {
                SetConsoleTextAttribute(hConsole, 2);
                std::cout << info.signatureStatus << "       ";
            }
            else if (info.signatureStatus == "Not signed") {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << info.signatureStatus << "   ";
            }
            else if (info.signatureStatus == "Deleted") {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << info.signatureStatus << "   ";
            }
            else {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << info.signatureStatus << "   ";
            }

            SetConsoleTextAttribute(hConsole, 7);
            std::cout << path << "   ";

            std::string filename;
            size_t pos = path.find_last_of("\\/");
            if (pos != std::string::npos) {
                filename = path.substr(pos + 1);
            }
            else {
                filename = path;
            }

            FindReplace(filename);

            if (info.signatureStatus != "Signed") {
                if (!iequals(path, getOwnPath())) {
                    if (!info.matched_rules.empty()) {
                        SetConsoleTextAttribute(hConsole, 4);
                        for (const auto& rule : info.matched_rules) {
                            std::cout << "[" << rule << "]";
                        }
                        SetConsoleTextAttribute(hConsole, 7);
                    }
                }
            }
            std::cout << std::endl;
        }
        else if (info.exists && !info.isValidMZ) {
            SetConsoleTextAttribute(hConsole, 2);
            std::cout << "File is present   ";
            SetConsoleTextAttribute(hConsole, 6);  
            std::cout << "Not MZ       ";       
            SetConsoleTextAttribute(hConsole, 7);  
            std::cout << path << std::endl;
        }
        else if (!info.exists) {
            SetConsoleTextAttribute(hConsole, 4);
            std::cout << "File is deleted   deleted      ";
            SetConsoleTextAttribute(hConsole, 7);
            std::cout << path << std::endl;
        }
    }

    DestroyReplaceParser();

    WriteAllReplacementsToFileAndPrintSummary();
    std::cout << "------End------";
    std::cin.ignore();
    return 0;
}

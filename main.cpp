#include "Include.h"
#include <fstream>

int main() {
    SetConsoleTitleA("Signatures tool, made by espouken");
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
        bool exists = file_exists(path);
        bool isValidMZ = exists && isMZFile(path);

        if (exists && isValidMZ) {
            std::string signatureStatus = getDigitalSignature(path);

            SetConsoleTextAttribute(hConsole, 2);
            std::cout << "File is present   ";

            if (signatureStatus == "Signed") {
                SetConsoleTextAttribute(hConsole, 2);
                std::cout << signatureStatus << "       ";
            }
            else if (signatureStatus == "Not signed") {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << signatureStatus << "   ";
            }
            else if (signatureStatus == "Deleted") {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << signatureStatus << "   ";
            }
            else {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << signatureStatus << "   ";
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

            if (signatureStatus != "Signed") {
                if (!iequals(path, getOwnPath())) {
                    std::vector<std::string> matched_rules;
                    bool yara_match = scan_with_yara(path, matched_rules);
                    if (yara_match) {
                        SetConsoleTextAttribute(hConsole, 4);
                        for (const auto& rule : matched_rules) {
                            std::cout << "[" << rule << "]";
                        }
                        SetConsoleTextAttribute(hConsole, 7);
                    }
                }
            }
            std::cout << std::endl;
        }
        else if (!exists) {
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
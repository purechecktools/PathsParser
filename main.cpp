#define NOMINMAX
#include "Include.h"


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
                if (info.signatureStatus != "Signed") {
                    if (!iequals(path, getOwnPath())) {
                        bool yara_match = scan_with_yara(path, info.matched_rules);
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache.try_emplace(path, info);
                auto it = fileCache.find(path);
                if (it != fileCache.end()) {
                    info = it->second;
                }
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
                else if (info.signatureStatus == "Deleted") {
                    SetConsoleTextAttribute(hConsole, 4);
                    std::cout << info.signatureStatus << "     ";
                }
                else {
                    SetConsoleTextAttribute(hConsole, 4);
                    std::cout << info.signatureStatus << "    ";
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
                std::cout << "File is present    ";
                SetConsoleTextAttribute(hConsole, 6);
                std::cout << "Not MZ        ";
                SetConsoleTextAttribute(hConsole, 7);
                std::cout << path << std::endl;
            }
            else if (!info.exists) {
                SetConsoleTextAttribute(hConsole, 4);
                std::cout << "File is deleted    deleted      ";
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
    

    if (scanMyYara)
        initializeGenericRules();

    if (scanOwnYara)
        initializateCustomRules();

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
        std::cout << "Press Enter to exit...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    const unsigned int num_threads = std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 1;
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    size_t total_paths = paths.size();
    size_t paths_per_thread = static_cast<size_t>(std::ceil(static_cast<double>(total_paths) / num_threads));
    size_t start_index = 0;

    std::cout << "Starting processing " << total_paths << " paths with " << num_threads << " threads..." << std::endl;

    for (unsigned int i = 0; i < num_threads && start_index < total_paths; ++i) {
        size_t end_index = std::min(start_index + paths_per_thread, total_paths);
        threads.emplace_back(process_paths_worker, std::ref(paths), start_index, end_index, hConsole);
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

    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "------End------" << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    return 0;
}
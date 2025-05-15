#include "Include.h"
#include "Replaceparser.h"


inline std::string replaceParserDir;
inline std::unordered_map<std::string, std::vector<ReplacementEntry>> replacementCache;
static std::map<std::pair<std::string, std::string>, ReplacementEntry> gLatestResults;

std::string ToLower(const std::string& str) {
	std::string result = str;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

bool isDllFile(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary);
	if (!file) {
		return false;
	}

	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
	if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	file.seekg(dosHeader.e_lfanew, std::ios::beg);
	uint32_t peSignature;
	file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
	if (!file || peSignature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	IMAGE_FILE_HEADER fileHeader;
	file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
	if (!file) {
		return false;
	}

	return (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}




bool WriteExeToTemp(const std::string& replaceParserDir) {
	std::string exePath = replaceParserDir + "\\replaceparser.exe";

	std::ofstream exeFile(exePath, std::ios::binary);
	if (!exeFile) {
		std::cerr << "Failed to create executable file: " << exePath << std::endl;
		return false;
	}

	exeFile.write(reinterpret_cast<const char*>(ReplaceParserHex), sizeof(ReplaceParserHex));
	exeFile.close();

	return true;
}

bool DeleteReplaceParserDir(const std::string& replaceParserDir) {
	try {
		std::filesystem::remove_all(replaceParserDir);
		return true;
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Error deleting directory " << replaceParserDir << ": " << e.what() << std::endl;
		return false;
	}
}

bool ExecuteReplaceParser(const std::string& replaceParserDir) {
	std::string exePath = replaceParserDir + "\\replaceparser.exe";
	std::string replacesTxtPath = replaceParserDir + "\\replaces.txt";
	std::string commandLine = "\"" + exePath + "\" \"" + replacesTxtPath + "\"";

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HANDLE hNull = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNull == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open NUL device." << std::endl;
		return false;
	}

	si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdOutput = hNull;
	si.hStdError = hNull;

	if (!CreateProcessA(
		NULL,
		const_cast<char*>(commandLine.c_str()),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		replaceParserDir.c_str(),
		&si,
		&pi
	)) {
		std::cerr << "Failed to execute replaceparser.exe. Error: " << GetLastError() << std::endl;
		CloseHandle(hNull);
		return false;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hNull);

	return true;
}

void PreProcessReplacements(const std::string& logFilePath) {
	std::ifstream file(logFilePath);
	if (!file.is_open()) {
		return;
	}
	std::string line;
	while (std::getline(file, line)) {
		if (line.empty()) continue;
		std::string replaceType, pattern;
		if (line.rfind("Explorer replacement found in file: ", 0) == 0) {
			replaceType = "Explorer";
			pattern = "Explorer replacement found in file: ";
		}
		else if (line.rfind("Copy replacement found in file: ", 0) == 0) {
			replaceType = "Copy";
			pattern = "Copy replacement found in file: ";
		}
		else if (line.rfind("Type pattern found in file: ", 0) == 0) {
			replaceType = "Type";
			pattern = "Type pattern found in file: ";
		}
		else if (line.rfind("Delete pattern found in file: ", 0) == 0) {
			replaceType = "Delete";
			pattern = "Delete pattern found in file: ";
		}
		else {
			continue;
		}
		size_t pos = line.find(pattern);
		if (pos == std::string::npos) continue;
		std::string foundFileName = line.substr(pos + pattern.size());
		std::string foundFileNameLower = ToLower(foundFileName);

		bool openBraceFound = false;
		std::string detailsCollected;
		std::string detailsLine;
		while (std::getline(file, detailsLine)) {
			if (!openBraceFound) {
				size_t bracePos = detailsLine.find('{');
				if (bracePos != std::string::npos) {
					openBraceFound = true;
					if (bracePos + 1 < detailsLine.size()) {
						detailsCollected += detailsLine.substr(bracePos + 1) + "\n";
					}
				}
			}
			else {
				size_t closePos = detailsLine.find('}');
				if (closePos != std::string::npos) {
					if (closePos > 0)
						detailsCollected += detailsLine.substr(0, closePos);
					break;
				}
				else {
					detailsCollected += detailsLine + "\n";
				}
			}
		}
		ReplacementEntry entry = { foundFileName, replaceType, detailsCollected };
		replacementCache[foundFileNameLower].push_back(entry);
	}
	file.close();
}

void FindReplace(const std::string& inputFileName) {
	std::string inputFileNameLower = ToLower(inputFileName);
	auto it = replacementCache.find(inputFileNameLower);
	if (it != replacementCache.end()) {
		for (const auto& entry : it->second) {
			std::pair<std::string, std::string> key = { entry.fileName, entry.replaceType };
			gLatestResults[key] = { entry.fileName, entry.replaceType, entry.details };
		}
	}
}

void WriteAllReplacementsToFileAndPrintSummary() {
	try {
		if (gLatestResults.empty()) {
			std::cout << "\n\nNo replacements found." << std::endl;
			return;
		}

		std::string outputFileName = "replaces.txt";
		std::ofstream outFile(outputFileName);

		if (!outFile.is_open()) {
			throw std::ios_base::failure("Failed to open the output file: " + outputFileName);
		}

		for (const auto& kv : gLatestResults) {
			outFile << "Found replacement type: " << kv.second.replaceType << "\n";
			outFile << "In file: " << kv.second.fileName << "\n";
			outFile << "Replacement details:\n" << kv.second.details << "\n\n";
		}

		outFile.close();

		std::cout << "\n\nFound " << gLatestResults.size() << " possible replacements, check " << outputFileName << std::endl;

		std::string command = "start \"\" \"" + outputFileName + "\"";
		int result = std::system(command.c_str());

		if (result != 0) {
			std::cerr << "Failed to open the file: " << outputFileName << std::endl;
		}
	}
	catch (const std::ios_base::failure& e) {
		std::cerr << "I/O error: " << e.what() << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
	}
	catch (...) {
		std::cerr << "An unknown error occurred." << std::endl;
	}
}


bool initReplaceParser() {
	char tempPathBuffer[MAX_PATH];
	DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPathBuffer);
	if (tempPathLen == 0 || tempPathLen > MAX_PATH) {
		std::cerr << "Failed to get temporary directory." << std::endl;
		return 1;
	}

	std::string tempPath = std::string(tempPathBuffer);
	if (tempPath.back() == '\\' || tempPath.back() == '/') {
		tempPath.pop_back();
	}

	replaceParserDir = tempPath + "\\replaceparser";
	if (!CreateDirectoryA(replaceParserDir.c_str(), NULL)) {
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			std::cerr << "Failed to create directory: " << replaceParserDir << std::endl;
			return 1;
		}
	}
	if (!WriteExeToTemp(replaceParserDir) || !ExecuteReplaceParser(replaceParserDir)) {
		return false;
	}
	return true;
}

bool DestroyReplaceParser() {
	if (!DeleteReplaceParserDir(replaceParserDir)) {
		std::cerr << "There was a problem deleting the replaceparser folder." << std::endl;
		return false;
	}
	return true;
}

__int64 privilege(const char* priv)
{
	HANDLE thandle;
	LUID identifier;
	TOKEN_PRIVILEGES privileges{};

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thandle)) {
		std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
		return 0;
	}

	if (!LookupPrivilegeValueA(nullptr, priv, &identifier)) {
		std::cerr << "LookupPrivilegeValueA error: " << GetLastError() << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = identifier;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(thandle, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
		std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	DWORD error = GetLastError();
	if (error == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "privileges error at assign." << std::endl;
		CloseHandle(thandle);
		return 0;
	}

	CloseHandle(thandle);
	return 1;
}

bool file_exists(const std::string& path) {
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string getOwnPath() {
	char buffer[MAX_PATH];
	DWORD filename = GetModuleFileNameA(NULL, buffer, MAX_PATH);

	return std::string(buffer, filename);
}

bool iequals(const std::string& a, const std::string& b) {
	return (a.size() == b.size()) &&
		std::equal(a.begin(), a.end(), b.begin(),
			[](char a, char b) {
				return std::tolower(a) == std::tolower(b);
			});
}

static bool VerifyFileViaCatalog(LPCWSTR filePath)
{
	HANDLE hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
		return false;

	HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	DWORD dwHashSize = 0;
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
	{
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	BYTE* pbHash = new BYTE[dwHashSize];
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
	{
		delete[] pbHash;
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	CloseHandle(hFile);

	CATALOG_INFO catInfo = { 0 };
	catInfo.cbStruct = sizeof(catInfo);

	HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
	bool isCatalogSigned = false;

	while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
	{
		WINTRUST_CATALOG_INFO wtc = {};
		wtc.cbStruct = sizeof(wtc);
		wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
		wtc.pbCalculatedFileHash = pbHash;
		wtc.cbCalculatedFileHash = dwHashSize;
		wtc.pcwszMemberFilePath = filePath;

		WINTRUST_DATA wtd = {};
		wtd.cbStruct = sizeof(wtd);
		wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wtd.pCatalog = &wtc;
		wtd.dwUIChoice = WTD_UI_NONE;
		wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wtd.dwProvFlags = 0;
		wtd.dwStateAction = WTD_STATEACTION_VERIFY;

		GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		LONG res = WinVerifyTrust(NULL, &action, &wtd);

		wtd.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &action, &wtd);

		if (res == ERROR_SUCCESS)
		{
			isCatalogSigned = true;
			break;
		}
		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
	}

	if (hCatInfo)
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

	CryptCATAdminReleaseContext(hCatAdmin, 0);
	delete[] pbHash;

	return isCatalogSigned;
}


std::string getDigitalSignature(const std::string& filePath) {
	WCHAR wideFilePath[MAX_PATH];
	if (MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideFilePath, MAX_PATH) == 0) {
		return "Not signed";
	}

	if (GetFileAttributesW(wideFilePath) == INVALID_FILE_ATTRIBUTES) {
		return "Not signed";
	}

	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = wideFilePath;

	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA winTrustData = {};
	winTrustData.cbStruct = sizeof(WINTRUST_DATA);
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pFile = &fileInfo;

	LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

	std::string result = "Not signed";
	PCCERT_CONTEXT signingCert = nullptr;

	if (status == ERROR_SUCCESS) {
		result = "Signed";

		CRYPT_PROVIDER_DATA const* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
		if (pProvData) {
			CRYPT_PROVIDER_DATA* nonConstData = const_cast<CRYPT_PROVIDER_DATA*>(pProvData);
			CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstData, 0, FALSE, 0);
			if (pProvSigner) {
				CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
				if (pProvCert && pProvCert->pCert) {
					signingCert = pProvCert->pCert;

					char subjName[256] = {};
					if (CertNameToStrA(
						signingCert->dwCertEncodingType,
						&signingCert->pCertInfo->Subject,
						CERT_X500_NAME_STR,
						subjName,
						sizeof(subjName)
					) > 1) {
						std::string subj(subjName);
						std::transform(subj.begin(), subj.end(), subj.begin(), ::tolower);
						static const char* cheats[] = {
							"manthe industries, llc",
							"slinkware",
							"amstion limited",
							"55.604.504 rafael ferreira de carvalho"
						};
						for (auto c : cheats) {
							if (subj.find(c) != std::string::npos) {
								result = "Cheat Signature";
								break;
							}
						}
					}

					DWORD hashLen = 0;
					if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
						std::vector<BYTE> hash(hashLen);
						if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
							CRYPT_HASH_BLOB blob = { hashLen, hash.data() };

							static const LPCWSTR storeNames[] = {
								L"MY", L"Root", L"Trust", L"CA", L"UserDS",
								L"TrustedPublisher", L"Disallowed", L"AuthRoot",
								L"TrustedPeople", L"ClientAuthIssuer",
								L"CertificateEnrollment", L"SmartCardRoot"
							};

							const DWORD contexts[] = {
								CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
								CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG
							};

							bool foundAnywhere = false;
							for (DWORD ctx : contexts) {
								for (auto storeName : storeNames) {
									HCERTSTORE hStore = CertOpenStore(
										CERT_STORE_PROV_SYSTEM_W,
										0,
										NULL,
										ctx,
										storeName
									);
									if (!hStore) {
										continue;
									}

									PCCERT_CONTEXT foundContext = CertFindCertificateInStore(
										hStore,
										signingCert->dwCertEncodingType,
										0,
										CERT_FIND_SHA1_HASH,
										&blob,
										NULL
									);
									if (foundContext) {
										foundAnywhere = true;
										CertFreeCertificateContext(foundContext);
									}
									CertCloseStore(hStore, 0);
									if (foundAnywhere) break;
								}
								if (foundAnywhere) break;
							}

							if (foundAnywhere) {
								result = "Fake Signature";
							}
						}
					}
				}
			}
		}
	}
	else {
		if (VerifyFileViaCatalog(wideFilePath)) {
			result = "Signed";
		}
		else {
			result = "Not signed";
		}
	}

	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &guidAction, &winTrustData);

	return result;
}

bool isMZFile(const std::string& path) {
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	WORD mzHeader;
	DWORD bytesRead;
	bool result = ReadFile(hFile, &mzHeader, sizeof(mzHeader), &bytesRead, NULL) &&
		bytesRead == sizeof(mzHeader) &&
		mzHeader == 0x5A4D;  // "MZ" in little-endian

	CloseHandle(hFile);
	return result;
}

std::string getOwnDirectory() {
	char buffer[MAX_PATH];
	DWORD filename = GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string path(buffer, filename);
	return path.substr(0, path.find_last_of("\\/") + 1);
}

bool hasInvalidSemicolonPath(const std::string& str) {
	size_t pos = 0;
	while ((pos = str.find(';', pos)) != std::string::npos) {
		if (str.substr(pos + 2, 2) == ":\\") {
			return true;
		}
		pos++;
	}

	return false;
}

bool isValidPathToProcess(const std::string& path, bool searchfordll) {

	if (path.ends_with("\\") && !file_exists(path)) {
		return false;
	}
	if (hasInvalidSemicolonPath(path)) {
		return false;
	}

	if (searchfordll)
		return isDllFile(path);
	else
		return true;
}


std::string extractValidPath(const std::string& line) {
	size_t colonSlashPos = line.find(":\\");
	if (colonSlashPos == std::string::npos)
		colonSlashPos = line.find(":/");

	if (colonSlashPos == std::string::npos || colonSlashPos == 0) {
		return "";
	}

	size_t lastSemicolonPos = line.find_last_of(";", colonSlashPos);
	if (lastSemicolonPos != std::string::npos) {
		return "";
	}

	char driveLetter = line[colonSlashPos - 1];
	if (!std::isalpha(driveLetter)) {
		return "";
	}

	std::string path = line.substr(colonSlashPos - 1);

	std::replace(path.begin(), path.end(), '/', '\\');
	if (!isValidPathToProcess(path, scanForDLLsOnly)) {
		return "";
	}

	return path;
}


bool is_directory(const std::string& path) {
	DWORD attributes = GetFileAttributesA(path.c_str());
	return (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

std::string rtrim(const std::string& s) {
	size_t end = s.find_last_not_of(" \t");
	return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::vector<std::string> readPathsFromFile(const std::string& filePath) {
	std::vector<std::string> paths;
	std::unordered_set<std::string> uniquePaths;
	std::ifstream file(filePath);
	std::string line;

	while (std::getline(file, line)) {
		line = rtrim(line);
		std::string path = extractValidPath(line);
		if (!path.empty() && uniquePaths.find(path) == uniquePaths.end()) {
			uniquePaths.insert(path);
			paths.push_back(path);
		}
	}
	return paths;
}

std::vector<std::string> getAllTargetPaths() {
	std::vector<std::string> allPaths;
	std::vector<std::string> targetFiles = {
		"search results.txt",
		"paths.txt",
		"p.txt"
	};

	std::string cDrive = "C:\\";
	for (const auto& fileName : targetFiles) {
		std::string fullPath = cDrive + fileName;
		if (file_exists(fullPath)) {
			std::cout << "Found and reading: " << fullPath << std::endl;
			auto paths = readPathsFromFile(fullPath);
			allPaths.insert(allPaths.end(), paths.begin(), paths.end());
		}
	}

	std::string ownDir = getOwnDirectory();
	for (const auto& fileName : targetFiles) {
		std::string fullPath = ownDir + fileName;
		if (file_exists(fullPath)) {
			std::cout << "Found and reading: " << fullPath << std::endl;
			auto paths = readPathsFromFile(fullPath);
			allPaths.insert(allPaths.end(), paths.begin(), paths.end());
		}
	}

	return allPaths;
}

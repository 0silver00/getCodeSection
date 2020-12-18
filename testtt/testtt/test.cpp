#define _CRT_SECURE_NO_WARNINGS
#include "framework.h"
#include <string>
#include <Psapi.h>
#include <Windows.h>
#include <tlhelp32.h>

void CodeSectionCheck();
BOOLEAN CompareCode(HANDLE hp, int pid, char filePath[], char fileName[], int firstIsExe, char ProcNameExe[]);
BOOL calcMD5(byte* data, LPSTR md5);
DWORD64 GetModuleAddress(const char* moduleName, int pid);

int main() {

	CodeSectionCheck();

	return 0;
}

void CodeSectionCheck() {
	int pid = GetCurrentProcessId();
	char filePath[MAX_PATH] = { 0, };
	char fileName[MAX_PATH] = { 0, };
	char ProcNameExe[MAX_PATH] = { 0, };
	int firstIsExe = -1;
	DWORD cbNeeded;

	HMODULE hMods[1024];
	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hp) {
		printf("FAILED OPENPROCESS\n");
	}

	// Get a list of all the modules in this process. 
	if (EnumProcessModules(hp, hMods, sizeof(hMods), &cbNeeded))
	{
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			//TCHAR szModName[MAX_PATH];
			firstIsExe++;
			// Get the full path to the module's file. 
			if (GetModuleFileNameEx(hp, hMods[i], filePath, sizeof(filePath) / sizeof(TCHAR)))
			{
				// Print the module name and handle value. 
				//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				GetFileTitle(filePath, fileName, sizeof(fileName));
				char tempfileName[256] = { 0, };
				memcpy(tempfileName, fileName, sizeof(fileName));
				if (firstIsExe == 0) {
					char* ptr2 = strtok(tempfileName, ".");
					memcpy(ProcNameExe, ptr2, strlen(tempfileName));
				}

				if (!strcmp(fileName, "Explorer.EXE")) {
					break;
				}
				if(!CompareCode(hp, pid, filePath, fileName, firstIsExe, ProcNameExe)) {
					printf("%s\n", fileName);
					printf("Failed CompareCode\n");
				}
			}
			else
				printf("failed get modulefilenameex\n");
		}
	}

	CloseHandle(hp);

}


//////////////////////
//////////////////////


BOOLEAN CompareCode(HANDLE hp, int pid, char filePath[], char fileName[], int firstIsExe, char ProcNameExe[]) {

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;

	void* lpBaseAddress = (void*)GetModuleAddress(fileName, pid);
	if (!lpBaseAddress) {
		printf("FAILED GETMODULEADDRESS\r\n");
		return FALSE;
	}

	/// <summary>
	/// Process PE (Memory)
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>

	BYTE* buf = (BYTE*)lpBaseAddress;
	BYTE* textAddr = NULL;
	int textSize;

	pDH = (PIMAGE_DOS_HEADER)buf;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Could not get IMAGE_DOS_HEADER\n");
		return FALSE;
	}
	else
		//printf("OK IMAGE_DOS_HEADER\n");

	pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Could not get IMAGE_NT_HEADER\n");
		return FALSE;
	}
	else
		//printf("OK IMAGE_NT_HEADER\n");

	pFH = &pNTH->FileHeader;
	pSH = IMAGE_FIRST_SECTION(pNTH);

	for (int i = 0; i < pFH->NumberOfSections; i++) {
		if (!strcmp((char*)pSH->Name, ".text")) {
			/*cout << "Section name:" << pSH->Name << endl;
			cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
			cout << "             Virtual address:" << pSH->VirtualAddress << endl;
			cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
			cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
			cout << "             Characteristics:" << pSH->Characteristics << endl;*/

			textAddr = (BYTE*)lpBaseAddress + pSH->VirtualAddress;
			textSize = pSH->Misc.VirtualSize;
			break;
		}
		pSH++;
	}


	/// <summary>
	/// Hashing
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>
	BYTE textSection[512] = { 0, };
	int HashNum = (textSize / 512) + 1;
	char md5[33];

	char makefile[256] = { 0, };
	char makefile2[256] = { 0, };
	char tempfileName[256] = { 0, };
	memcpy(tempfileName, fileName, sizeof(fileName));
	char* ptr = strtok(tempfileName, ".");    //첫번째 strtok 사용.
	//printf("%s\n", ptr);         //자른 문자 출력
	//ptr = strtok(NULL, " ");     //자른 문자 다음부터 구분자 또 찾기
	//printf("%s\n", fileName);
	if (firstIsExe == 0) {
		sprintf_s(makefile, "%d_%s", pid, tempfileName);
		printf("%s\n", makefile);
	}
	else {
		sprintf_s(makefile, "%d_%s_%s", pid, ProcNameExe, tempfileName);
		printf("%s\n", makefile);
	}

	FILE* fp;
	sprintf_s(makefile2, ".\\temp\\%s.txt", makefile);
	fp = fopen(makefile2, "w+");

	//BYTE* textAddrTmp = textAddr;

	for (int i = 0; i < HashNum; i++) {
		//해당 process라서 readprocessmemory 안해도 됨, textAddr부터 textAddr+textSize 만큼 512byte씩 읽어오면서 해싱작업
		//그리고, "pid_프로세스_dll이름.txt"로 해시 값 출력
		//
		memcpy(textSection, textAddr, 512);

		if (calcMD5(textSection, md5)) {
			//printf("%s\n", md5);
			fputs(md5, fp);
			textAddr = textAddr + 512;
		}
		else {
			printf("MD5 calculation failed.\n");
			return false;
		}
	}

	fclose(fp);
	return true;
}


//BYTE buff[512];
BOOL calcMD5(byte* data, LPSTR md5)
{

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf("ERROR: Couldn't acquire crypto context!\n");
		return FALSE;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		printf("ERROR: Couldn't create crypto stream!\n");
		return FALSE;
	}

	if (!CryptHashData(hHash, data, 512, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		printf("ERROR: CryptHashData failed!\n");
		return FALSE;
	}

	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf(md5 + (i * 2), "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return TRUE;
	}
	else
	{
		printf("ERROR: CryptHashData failed!\n");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
}


DWORD64 GetModuleAddress(const char* moduleName, int pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(snapshot, &moduleEntry);
	do
	{
		if (!strcmp(moduleName, moduleEntry.szModule))
		{
			CloseHandle(snapshot);
			return (DWORD64)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(snapshot, &moduleEntry));

	CloseHandle(snapshot);
}
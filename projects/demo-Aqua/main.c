#include <Aqua.h>
#include <ntdll.h>
#include <stdio.h>

HANDLE RCreateFile(LPCWSTR wszDllPath,LPVOID *outBuffer) {
	HANDLE hFile = CreateFileW(wszDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (INVALID_HANDLE_VALUE == hFile || NULL == hFile) {
		wprintf(L"Failed to open the file: %s\r\n", wszDllPath);
		return INVALID_HANDLE_VALUE;
}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (INVALID_FILE_SIZE == dwFileSize || dwFileSize < sizeof(IMAGE_DOS_HEADER)) {
		CloseHandle(hFile);
		printf(("Invalid file size: %d\r\n"), dwFileSize);
		return INVALID_HANDLE_VALUE;
	}

	HANDLE hFileMapping = CreateFileMappingW(hFile, 0, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hFileMapping) {
		CloseHandle(hFile);
		printf(("Failed to create file mapping.\r\n"));
		return INVALID_HANDLE_VALUE;
	}

	LPVOID pBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pBuffer) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		printf(("Failed to map view of the file.\r\n"));
		return INVALID_HANDLE_VALUE;
	}

	*outBuffer = pBuffer;
	return hFile;
}

typedef BOOL(WINAPI* FuncAquaSuki)(char* n);
typedef void (WINAPI* FuncDaregakawai)(char* say, char* reply, size_t replySize);

int main() {
#ifdef _WIN64
#ifdef _DEBUG
	WCHAR wszDllPath[] = L"..\\..\\out\\x64\\Debug\\Aqua-daisuki.dll";
#else
	WCHAR wszDllPath[] = L"..\\..\\out\\x64\\Release\\Aqua-daisuki.dll";
#endif
#else
#ifdef _DEBUG
	WCHAR wszDllPath[] = L"..\\..\\out\\x86\\Debug\\Aqua-daisuki.dll";
#else
	WCHAR wszDllPath[] = L"..\\..\\out\\x86\\Release\\Aqua-daisuki.dll";
#endif
#endif
	
	LPVOID pBuffer = NULL;
	if (INVALID_HANDLE_VALUE==RCreateFile(wszDllPath, &pBuffer) || pBuffer == NULL) {
		printf("Open File Fail!");
		return -1;
	}

	DWORD error = 0;
	HAQUAMODULE aquaModule = LoadMemModule(pBuffer, TRUE, &error);
	if (aquaModule) {

		FuncAquaSuki funcAquaSuki = (FuncAquaSuki)GetMemModuleProc(aquaModule, "AquaSuki");
		if (funcAquaSuki) {
			printf("funcAquaSuki(\"suki\") = %d\r\n", funcAquaSuki("suki"));
		}
		FuncDaregakawai funcDaregakawai = (FuncDaregakawai)GetMemModuleProc(aquaModule, "Daregakawai");
		if (funcDaregakawai) {
			char reply[1024];
			memset(reply, 0, sizeof(reply));
			funcDaregakawai("aqua", reply, sizeof(reply));
			printf("funcDaregakawai(\"aqua\") = %s\r\n", reply);
			memset(reply, 0, sizeof(reply));
			funcDaregakawai("alice", reply, sizeof(reply));
			printf("funcDaregakawai(\"alice\") = %s\r\n", reply);
		}
		FreeMemModule(aquaModule);
	}
	else {
		printf("Aqua loader fail: %d\r\n", error);
	}

	return 0;
}
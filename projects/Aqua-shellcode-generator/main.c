#include <Aqua.h>
#include <ntdll.h>
#include <stdio.h>

LPVOID AquaModuleHelper(_In_ AMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3);
void AquaModuleHelperEnd();

LPSTR shellcodeHeader = "/****************************************************************/\r\n"
"/*\r\n"
"MIT License\r\n"
"\r\n"
"Copyright (c) 2017 Sheen\r\n"
"Copyright (c) 2020 aphage\r\n"
"\r\n"
"Permission is hereby granted, free of charge, to any person obtaining a copy\r\n"
"of this software and associated documentation files (the \"Software\"), to deal\r\n"
"in the Software without restriction, including without limitation the rights\r\n"
"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\r\n"
"copies of the Software, and to permit persons to whom the Software is\r\n"
"furnished to do so, subject to the following conditions: \r\n"
"\r\n"
"The above copyright notice and this permission notice shall be included in all\r\n"
"copies or substantial portions of the Software.\r\n"
"\r\n"
"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\r\n"
"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, \r\n"
"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\r\n"
"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\r\n"
"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, \r\n"
"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\r\n"
"SOFTWARE.\r\n"
"*/ \r\n"
"\r\n"
"\r\n"
"#ifdef __cplusplus\r\n"
"extern \"C\" {\r\n"
"#endif\r\n"
"\r\n"
"#define AQUA_ERROR_OK 0\r\n"
"#define AQUA_ERROR_BAD_PE_FORMAT 1\r\n"
"#define AQUA_ERROR_ALLOCATED_MEMORY_FAILED 2\r\n"
"#define AQUA_ERROR_INVALID_RELOCATION_BASE 3\r\n"
"#define AQUA_ERROR_IMPORT_MODULE_FAILED 4\r\n"
"#define AQUA_ERROR_PROTECT_SECTION_FAILED 5\r\n"
"#define AQUA_ERROR_INVALID_ENTRY_POINT 6\r\n"
"#define AQUA_ERROR_INVALID_ENV 0xff\r\n"
"\r\n"
"	typedef enum _AQUAHELPER_METHOD {\r\n"
"		AHM_LOAD_MODULE,\r\n"
"		AHM_FREE_VOID,\r\n"
"		AHM_GETPROC_FARPROC\r\n"
"	}AMHELPER_METHOD;\r\n"
"\r\n"
"	typedef void** HAQUAMODULE;\r\n"
"\r\n"
"	typedef LPVOID(* FuncMemModuleHelper)(AMHELPER_METHOD, LPVOID, LPVOID, LPVOID);\r\n"
"\r\n"
"\r\n"
"\r\n"
"unsigned char aquaShellCode[] = {\r\n";

LPSTR shellcodeEnd = "\r\n};\r\n"
"\r\n"
"#ifdef __cplusplus\r\n"
"}\r\n"
"#endif\r\n";

#ifdef _WIN64
#ifdef _DEBUG
#define SHELLCODE_FILE_NAME "../../out/aquaShellCode-x64-Debug.h"
#else
#define SHELLCODE_FILE_NAME "../../out/aquaShellCode-x64-Release.h"
#endif
#else
#ifdef _DEBUG
#define SHELLCODE_FILE_NAME "../../out/aquaShellCode-x86-Debug.h"
#else
#define SHELLCODE_FILE_NAME "../../out/aquaShellCode-x86-Release.h"
#endif
#endif

int main() {

	PBYTE pStart = (PBYTE)&AquaModuleHelper;
	PBYTE pEnd = (PBYTE)&AquaModuleHelperEnd;
	DWORD size = (DWORD)(pEnd - pStart);

	HANDLE hFile = CreateFileA(SHELLCODE_FILE_NAME, FILE_WRITE_ACCESS, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("CreateFile Error %d\n", GetLastError());
		return -1;
	}
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	DWORD dwBytesWritten = 0;
	WriteFile(hFile, shellcodeHeader, strlen(shellcodeHeader), &dwBytesWritten, NULL);
	printf("%s", shellcodeHeader);
	for (DWORD i = 0; i < size; i++) {
		if (i == size - 1)
			sprintf_s(buffer, 1024, "0x%02X", pStart[i]);
		else if (i % 16 == 0)
			sprintf_s(buffer, 1024, "0x%02X,\r\n", pStart[i]);
		else
			sprintf_s(buffer, 1024, "0x%02X, ", pStart[i]);
		WriteFile(hFile, buffer, strlen(buffer), &dwBytesWritten, NULL);
		printf("%s", buffer);
	}
	WriteFile(hFile, shellcodeEnd, strlen(shellcodeEnd), &dwBytesWritten, NULL);
	printf("%s", shellcodeEnd);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);

	printf("\r\n\r\n//Generate into ./out directory\r\n");
	printf("//shellcode size: %d\r\n", size);
	return 0;
}
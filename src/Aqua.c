/*
MIT License

Copyright (c) 2017 Sheen
Copyright (c) 2020 aphage

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#include "ntdll.h"
#include "Aqua.h"


#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

void* aqua_memmove(void* dest, const void* src, size_t len);
void* aqua_memset(void* dest, int val, size_t len);
wchar_t* aqua_strtowcs(wchar_t* d, const char* t, size_t len);
__forceinline
int aqua_tolower(int c);
int aqua_strcmp(const char* s1, const char* s2);
size_t aqua_strlen(const char* str);
int aqua_wcsicmp(const wchar_t* cs, const wchar_t* ct);

typedef struct _API_TABLE {
	FuncLdrLoadDll funcLdrLoadDll;
	FuncLdrGetProcedureAddress funcLdrGetProcedureAddress;

	FuncNtAllocateVirtualMemory funcNtAllocateVirtualMemory;
	FuncNtFreeVirtualMemory funcNtFreeVirtualMemory;
	FuncNtProtectVirtualMemory funcNtProtectVirtualMemory;
}API_TABLE, * PAPI_TABLE;

typedef struct _AQUA_MODULE {
	union {
#if _WIN64
		ULONGLONG iBase;
#else
		DWORD iBase;
#endif
		HMODULE hModule;
		LPVOID lpBase;
		PIMAGE_DOS_HEADER pImageDosHeader;
	};                   // MemModule base
	DWORD dwSizeOfImage; // MemModule size
	DWORD dwCrc;         // MemModule crc32

	PAPI_TABLE pApis;	// Pointer to parameters
	BOOL bCallEntry;     // Call module entry
	BOOL bLoadOk;        // MemModule is loaded ok?
	DWORD dwErrorCode;   // Last error code
}AQUA_MODULE, * PAQUA_MODULE;


LPVOID AquaModuleHelper(_In_ AMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3) {
	switch (method) {
	case AHM_LOAD_MODULE: {
		return (LPVOID)(INT_PTR)LoadMemModule(lpArg1, (BOOL)lpArg2, (DWORD*)lpArg3);
	} break;
	case AHM_FREE_VOID: {
		FreeMemModule(lpArg1);
	} break;
	case AHM_GETPROC_FARPROC: {
		return (LPVOID)GetMemModuleProc(lpArg1, lpArg2);
	} break;
	default:
		break;
	}

	return 0;
}

#ifdef _WIN64
__forceinline struct _TEB* RCurrentTeb() { return (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self)); }
#else
__forceinline struct _TEB* RCurrentTeb() { return (struct _TEB*) (ULONG_PTR) __readfsdword(PcTeb); }
#endif

__forceinline PPEB RGetCurrentPeb() { return RCurrentTeb()->ProcessEnvironmentBlock; }

LPVOID RVirtualAlloc(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect,
	_In_ FuncNtAllocateVirtualMemory funcNtAllocateVirtualMemory) {

	if (!funcNtAllocateVirtualMemory)
		return NULL;
	NTSTATUS status = funcNtAllocateVirtualMemory(NtCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect);
	return NT_SUCCESS(status) ? lpAddress : NULL;
}

BOOL RVirtualFree(
	_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType,
	_In_ FuncNtFreeVirtualMemory funcNtFreeVirtualMemory) {

	if (!funcNtFreeVirtualMemory)
		return FALSE;
	NTSTATUS status = funcNtFreeVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, dwFreeType);
	return NT_SUCCESS(status);
}

BOOL
RVirtualProtect(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect,
	_In_ FuncNtProtectVirtualMemory funcNtProtectVirtualMemory)
{
	if (!funcNtProtectVirtualMemory)
		return FALSE;
	NTSTATUS status = funcNtProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
	return NT_SUCCESS(status);
}

FARPROC RLdrGetProcedureAddress(HMODULE hModule, LPSTR name, WORD number, FuncLdrGetProcedureAddress funcLdrGetProcedureAddress) {
	if (!funcLdrGetProcedureAddress || !hModule)
		return NULL;
	PVOID n = NULL;
	NTSTATUS status = 0;
	if (name == NULL) {
		status = funcLdrGetProcedureAddress(hModule, NULL, number, &n);
	}
	else {
		ANSI_STRING fName;
		fName.Buffer = name;
		fName.Length = fName.MaximumLength = (USHORT)aqua_strlen(name);

		status = funcLdrGetProcedureAddress(hModule, &fName, 0, &n);
	}

	if (NT_SUCCESS(status))
		return (FARPROC)n;
	return NULL;
}

HMODULE RLdrLoadDll(_In_ LPSTR lpDllName, _In_ FuncLdrLoadDll funcLdrLoadDll)
{
	if (NULL == lpDllName || NULL == funcLdrLoadDll)
		return NULL;
	wchar_t tempDllName[256];

	aqua_memset(tempDllName, 0, sizeof(tempDllName));

	aqua_strtowcs(tempDllName, lpDllName, aqua_strlen(lpDllName) + 1);

	UNICODE_STRING dllName;
	dllName.MaximumLength = dllName.Length = (USHORT)(aqua_strlen(lpDllName) * sizeof(wchar_t));
	dllName.Buffer = tempDllName;

	PVOID hModule = NULL;
	NTSTATUS status = funcLdrLoadDll(NULL, 0, &dllName, &hModule);

	return NT_SUCCESS(status) ? (HMODULE)hModule : NULL;
}

BOOL RIsValidPEFormat(_In_ LPVOID lpPeModuleBuffer) {
	if (NULL == lpPeModuleBuffer)
		return FALSE;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpPeModuleBuffer;
	if (IMAGE_DOS_SIGNATURE != pImageDosHeader->e_magic)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pImageNtHeader->Signature)
		return FALSE;

	if (!(IMAGE_FILE_EXECUTABLE_IMAGE & pImageNtHeader->FileHeader.Characteristics))
		return FALSE;

	if (sizeof(IMAGE_OPTIONAL_HEADER) != pImageNtHeader->FileHeader.SizeOfOptionalHeader)
		return FALSE;

	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pImageNtHeader->OptionalHeader.Magic &&
		IMAGE_NT_OPTIONAL_HDR64_MAGIC != pImageNtHeader->OptionalHeader.Magic)
		return FALSE;

	return TRUE;
}

HMODULE RGetModuleHandleW(LPWSTR dllName) {

	if (dllName == NULL)
		return NULL;

	PPEB pPeb = RGetCurrentPeb();

	if (pPeb && pPeb->Ldr) {
		PPEB_LDR_DATA pLdrData = pPeb->Ldr;

		PLIST_ENTRY pHeaderOfMoudleList = &(pLdrData->InLoadOrderModuleList);

		if (pHeaderOfMoudleList->Flink != pHeaderOfMoudleList) {
			PLDR_DATA_TABLE_ENTRY pEntry = NULL;
			PLIST_ENTRY pCur = pHeaderOfMoudleList->Flink;

			do {
				pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (0 == aqua_wcsicmp(pEntry->BaseDllName.Buffer, dllName)) {
					return (HMODULE)pEntry->DllBase;
				}
				pCur = pCur->Flink;
			} while (pCur != pHeaderOfMoudleList);
		}
	}
	return NULL;
}

HMODULE RGetModuleHandleA(LPSTR dllName) {
	wchar_t tempDllName[256];
	aqua_memset(tempDllName, 0, sizeof(tempDllName));

	aqua_strtowcs(tempDllName, dllName, aqua_strlen(dllName) + 1);

	return RGetModuleHandleW(tempDllName);
}

FARPROC RGetProcAddress(HMODULE hModule, LPSTR name, WORD number) {

	if (hModule == NULL || (name == NULL && number == 0))
		return NULL;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;

	if (!RIsValidPEFormat(pImageDosHeader))
		return NULL;

	PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (0 == pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ||
		0 == pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
		MakePointer(PIMAGE_EXPORT_DIRECTORY, hModule, pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
	PDWORD pFuncNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);
	PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);

	DWORD addressOffset = 0;
	if (name == NULL && number >= pImageExportDirectory->Base) {
		if (pImageExportDirectory->NumberOfFunctions > (number - pImageExportDirectory->Base))
			addressOffset = pAddressTable[number - pImageExportDirectory->Base];
		else
			return NULL;
	}
	else {
		for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; ++i) {
			if (0 == aqua_strcmp(name, (char*)hModule + pFuncNameTable[i])) {
				addressOffset = pAddressTable[pOrdinalTable[i]];
			}
		}
	}

	if (0 == addressOffset)
		return NULL;

	//is forward
	if (addressOffset > pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
		addressOffset < (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {

		return NULL;
	}
	return MakePointer(FARPROC, hModule, addressOffset);
}

PAPI_TABLE InitApiTable() {

	WCHAR wszNtdll[] = { 'n','t','d','l','l','.','d','l','l' ,0 };

	HMODULE hNtdll = RGetModuleHandleW(wszNtdll);

	if (hNtdll == NULL)
		return NULL;

	char szLdrLoadDll[] = { 'L','d','r','L','o','a','d','D','l','l',0 };
	FuncLdrLoadDll funcLdrLoadDll = (FuncLdrLoadDll)RGetProcAddress(hNtdll, szLdrLoadDll, 0);
	if (funcLdrLoadDll == NULL)
		return NULL;

	char szLdrGetProcedureAddress[] = { 'L','d','r','G','e','t','P','r','o','c','e','d','u','r','e','A','d','d','r','e','s','s',0 };
	FuncLdrGetProcedureAddress funcLdrGetProcedureAddress = (FuncLdrGetProcedureAddress)RGetProcAddress(hNtdll, szLdrGetProcedureAddress, 0);
	if (funcLdrGetProcedureAddress == NULL)
		return NULL;

	char szNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	FuncNtAllocateVirtualMemory funcNtAllocateVirtualMemory = (FuncNtAllocateVirtualMemory)RGetProcAddress(hNtdll, szNtAllocateVirtualMemory, 0);
	if (funcNtAllocateVirtualMemory == NULL)
		return NULL;

	char szNtFreeVirtualMemory[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	FuncNtFreeVirtualMemory funcNtFreeVirtualMemory = (FuncNtFreeVirtualMemory)RGetProcAddress(hNtdll, szNtFreeVirtualMemory, 0);
	if (funcNtFreeVirtualMemory == NULL)
		return NULL;

	char szNtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	FuncNtProtectVirtualMemory funcNtProtectVirtualMemory = (FuncNtProtectVirtualMemory)RGetProcAddress(hNtdll, szNtProtectVirtualMemory, 0);
	if (funcNtProtectVirtualMemory == NULL)
		return NULL;

	PAPI_TABLE pApis = RVirtualAlloc(NULL, sizeof(API_TABLE), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, funcNtAllocateVirtualMemory);
	if (NULL == pApis)
		return NULL;

	pApis->funcLdrLoadDll = funcLdrLoadDll;
	pApis->funcLdrGetProcedureAddress = funcLdrGetProcedureAddress;
	pApis->funcNtAllocateVirtualMemory = funcNtAllocateVirtualMemory;
	pApis->funcNtFreeVirtualMemory = funcNtFreeVirtualMemory;
	pApis->funcNtProtectVirtualMemory = funcNtProtectVirtualMemory;

	return pApis;
}

BOOL MapMemModuleSections(PAQUA_MODULE pAquaModule, LPVOID lpPeModuleBuffer) {
	if (NULL == pAquaModule || NULL == pAquaModule->pApis || NULL == lpPeModuleBuffer)
		return FALSE;

	// Convert to IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpPeModuleBuffer);

	// Get the pointer to IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

	// Get the section count
	int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;

	// Get the section header
	PIMAGE_SECTION_HEADER pImageSectionHeader =
		MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	// Find the last section limit
	DWORD dwImageSizeLimit = 0;
	for (int i = 0; i < nNumberOfSections; ++i) {
		if (0 != pImageSectionHeader[i].VirtualAddress) {
			if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
				dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
		}
	}

	// Remove. The VirtualAlloc will do this for use
	// Align the last image size limit to the page size
	// dwImageSizeLimit = dwImageSizeLimit + pAquaModule->pParams->dwPageSize - 1;
	// dwImageSizeLimit &= ~(pAquaModule->pParams->dwPageSize - 1);

	// Reserve virtual memory
	LPVOID lpBase = RVirtualAlloc((LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), dwImageSizeLimit,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, pAquaModule->pApis->funcNtAllocateVirtualMemory);

	// Failed to reserve space at ImageBase, then it's up to the system
	if (NULL == lpBase) {
		// Reserver memory in arbitrary address
		lpBase = RVirtualAlloc(NULL, dwImageSizeLimit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, pAquaModule->pApis->funcNtAllocateVirtualMemory);

		// Failed again, return
		if (NULL == lpBase) {
			pAquaModule->dwErrorCode = AQUA_ERROR_ALLOCATED_MEMORY_FAILED;
			return FALSE;
		}
	}

	// Commit memory for PE header
	LPVOID pDest = RVirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE, pAquaModule->pApis->funcNtAllocateVirtualMemory);
	if (!pDest) {
		pAquaModule->dwErrorCode = AQUA_ERROR_ALLOCATED_MEMORY_FAILED;
		return FALSE;
	}

	// Copy the data of PE header to the memory allocated
	aqua_memmove(pDest, lpPeModuleBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);

	// Store the base address of this module.
	pAquaModule->lpBase = pDest;
	pAquaModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
	pAquaModule->bLoadOk = TRUE;

	// Get the DOS header, NT header and Section header from the new PE header
	// buffer
	pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
	pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
	pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	// Map all section data into the memory
	LPVOID pSectionBase = NULL;
	LPVOID pSectionDataSource = NULL;
	for (int i = 0; i < nNumberOfSections; ++i) {
		if (0 != pImageSectionHeader[i].VirtualAddress) {
			// Get the section base
			pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

			if (0 == pImageSectionHeader[i].SizeOfRawData) {
				DWORD size = 0;
				if (pImageSectionHeader[i].Misc.VirtualSize > 0) {
					size = pImageSectionHeader[i].Misc.VirtualSize;
				}
				else {
					size = pImageNtHeader->OptionalHeader.SectionAlignment;
				}

				if (size > 0) {
					// If the size is zero, but the section alignment is not zero then
					// allocate memory with the alignment
					pDest = RVirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE, pAquaModule->pApis->funcNtAllocateVirtualMemory);
					if (NULL == pDest) {
						pAquaModule->dwErrorCode = AQUA_ERROR_ALLOCATED_MEMORY_FAILED;
						return FALSE;
					}

					// Always use position from file to support alignments smaller than
					// page size.
					aqua_memset(pSectionBase, 0, size);
				}
			}
			else {
				// Commit this section to target address
				pDest = RVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE, pAquaModule->pApis->funcNtAllocateVirtualMemory);
				if (NULL == pDest) {
					pAquaModule->dwErrorCode = AQUA_ERROR_ALLOCATED_MEMORY_FAILED;
					return FALSE;
				}

				// Get the section data source and copy the data to the section buffer
				pSectionDataSource = MakePointer(LPVOID, lpPeModuleBuffer, pImageSectionHeader[i].PointerToRawData);
				aqua_memmove(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
			}

			// Get next section header
			pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
		}
	}

	return TRUE;
}

BOOL RelocateModuleBase(PAQUA_MODULE pAquaModule) {
	// Validate the parameters
	if (NULL == pAquaModule || NULL == pAquaModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader =
		MakePointer(PIMAGE_NT_HEADERS, pAquaModule->pImageDosHeader, pAquaModule->pImageDosHeader->e_lfanew);

	// Get the delta of the real image base with the predefined
	LONGLONG lBaseDelta = ((PBYTE)pAquaModule->iBase - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase);

	// This module has been loaded to the ImageBase, no need to do relocation
	if (0 == lBaseDelta)
		return TRUE;

	if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
		0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return TRUE;

	PIMAGE_BASE_RELOCATION pImageBaseRelocation =
		MakePointer(PIMAGE_BASE_RELOCATION, pAquaModule->lpBase,
			pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (NULL == pImageBaseRelocation) {
		pAquaModule->dwErrorCode = AQUA_ERROR_INVALID_RELOCATION_BASE;
		return FALSE;
	}

	while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock)) {
		PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

		int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < NumberOfRelocationData; i++) {
			if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) {
				PDWORD pAddress =
					(PDWORD)(pAquaModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
				*pAddress += (DWORD)lBaseDelta;
			}

#ifdef _WIN64
			if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) {
				PULONGLONG pAddress =
					(PULONGLONG)(pAquaModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
				*pAddress += lBaseDelta;
			}
#endif
		}

		pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
	}

	return TRUE;
}

BOOL ResolveImportTable(PAQUA_MODULE pAquaModule) {
	if (NULL == pAquaModule || NULL == pAquaModule->pApis || NULL == pAquaModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader =
		MakePointer(PIMAGE_NT_HEADERS, pAquaModule->pImageDosHeader, pAquaModule->pImageDosHeader->e_lfanew);

	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return TRUE;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =
		MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pAquaModule->lpBase,
			pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {
		// Get the dependent module name
		PCHAR pDllName = MakePointer(PCHAR, pAquaModule->lpBase, pImageImportDescriptor->Name);

		// Get the dependent module handle
		HMODULE hMod = RGetModuleHandleA(pDllName);

		// Load the dependent module
		if (NULL == hMod)
			hMod = RLdrLoadDll(pDllName, pAquaModule->pApis->funcLdrLoadDll);

		// Failed
		if (NULL == hMod) {
			pAquaModule->dwErrorCode = AQUA_ERROR_IMPORT_MODULE_FAILED;
			return FALSE;
		}
		// Original thunk
		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDescriptor->OriginalFirstThunk)
			pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pAquaModule->lpBase, pImageImportDescriptor->OriginalFirstThunk);
		else
			pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pAquaModule->lpBase, pImageImportDescriptor->FirstThunk);

		// IAT thunk
		PIMAGE_THUNK_DATA pIATThunk =
			MakePointer(PIMAGE_THUNK_DATA, pAquaModule->lpBase, pImageImportDescriptor->FirstThunk);

		for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
				lpFunction = RLdrGetProcedureAddress(hMod, NULL,(WORD)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal), pAquaModule->pApis->funcLdrGetProcedureAddress);
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageImportByName =
					MakePointer(PIMAGE_IMPORT_BY_NAME, pAquaModule->lpBase, pOriginalThunk->u1.AddressOfData);

				lpFunction = RLdrGetProcedureAddress(hMod, (LPSTR) & (pImageImportByName->Name), 0, pAquaModule->pApis->funcLdrGetProcedureAddress);
			}

			// Write into IAT
#ifdef _WIN64
			pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
			pIATThunk->u1.Function = (DWORD)lpFunction;
#endif
		}
	}

	return TRUE;
}

BOOL SetMemProtectStatus(PAQUA_MODULE pAquaModule) {
	if (NULL == pAquaModule || NULL == pAquaModule->pApis)
		return FALSE;

	int ProtectionMatrix[2][2][2] = {
		{
			// not executable
			{PAGE_NOACCESS, PAGE_WRITECOPY},
			{PAGE_READONLY, PAGE_READWRITE},
		},
		{
			// executable
			{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
			{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
		},
	};

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pAquaModule->lpBase);

	ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
	ulBaseHigh = (pAquaModule->iBase & 0xffffffff00000000);
#endif

	PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

	int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader =
		MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

	for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) {
		DWORD protectFlag = 0;
		DWORD oldProtect = 0;
		BOOL isExecutable = FALSE;
		BOOL isReadable = FALSE;
		BOOL isWritable = FALSE;

		BOOL isNotCache = FALSE;
		ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
		DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
		if (0 == dwSecionSize)
			continue;

		// This section is in this page
		DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

		// Discardable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			RVirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT, pAquaModule->pApis->funcNtFreeVirtualMemory);
			continue;
		}

		// Executable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			isExecutable = TRUE;

		// Readable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
			isReadable = TRUE;

		// Writable
		if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			isWritable = TRUE;

		if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
			isNotCache = TRUE;

		protectFlag = ProtectionMatrix[isExecutable][isReadable][isWritable];
		if (isNotCache)
			protectFlag |= PAGE_NOCACHE;
		if (!RVirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect,pAquaModule->pApis->funcNtProtectVirtualMemory)) {
			pAquaModule->dwErrorCode = AQUA_ERROR_PROTECT_SECTION_FAILED;
			return FALSE;
		}
	}

	return TRUE;
}

BOOL ExecuteTLSCallback(PAQUA_MODULE pAquaModule) {
	if (NULL == pAquaModule || NULL == pAquaModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader =
		MakePointer(PIMAGE_NT_HEADERS, pAquaModule->pImageDosHeader, pAquaModule->pImageDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (imageDirectoryEntryTls.VirtualAddress == 0)
		return TRUE;

	PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pAquaModule->iBase + imageDirectoryEntryTls.VirtualAddress);
	PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
	if (callback) {
		while (*callback) {
			(*callback)((LPVOID)pAquaModule->hModule, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
	}
	return TRUE;
}

BOOL CallModuleEntry(PAQUA_MODULE pAquaModule, DWORD dwReason) {
	if (NULL == pAquaModule || NULL == pAquaModule->pImageDosHeader)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader =
		MakePointer(PIMAGE_NT_HEADERS, pAquaModule->pImageDosHeader, pAquaModule->pImageDosHeader->e_lfanew);

	// If there is no entry point return false
	if (0 == pImageNtHeader->OptionalHeader.AddressOfEntryPoint) {
		pAquaModule->dwErrorCode = AQUA_ERROR_INVALID_ENTRY_POINT;
		return FALSE;
	}

	FuncDllMain pfnModuleEntry = MakePointer(FuncDllMain, pAquaModule->lpBase, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

	return pfnModuleEntry(pAquaModule->hModule, dwReason, NULL);
}

VOID UnmapMemModule(PAQUA_MODULE pAquaModule) {
	if (NULL == pAquaModule || NULL == pAquaModule->pApis || FALSE == pAquaModule->bLoadOk || NULL == pAquaModule->lpBase)
		return;

	RVirtualFree(pAquaModule->lpBase, 0, MEM_RELEASE, pAquaModule->pApis->funcNtFreeVirtualMemory);

	pAquaModule->lpBase = NULL;
	pAquaModule->dwCrc = 0;
	pAquaModule->dwSizeOfImage = 0;
	pAquaModule->bLoadOk = FALSE;
}

UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize) {
#define CRC32_POLY 0x04C10DB7L
	UINT32 crc = 0;
	UINT32 Crc32table[256];
	for (int i = 0; i < 256; i++) {
		crc = (UINT32)(i << 24);
		for (int j = 0; j < 8; j++) {
			if (crc >> 31)
				crc = (crc << 1) ^ CRC32_POLY;
			else
				crc = crc << 1;
		}
		Crc32table[i] = crc;
	}

	crc = uInit;
	UINT32 nCount = nBufSize;
	PUCHAR p = (PUCHAR)pBuf;
	while (nCount--) {
		crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
	}

	return crc;
}

HAQUAMODULE LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD* pdwError) {
	PAPI_TABLE pApis = InitApiTable();
	if (!pApis) {
		if (pdwError)
			*pdwError = AQUA_ERROR_INVALID_ENV;
		return NULL;
	}

	PAQUA_MODULE pAquaModule = RVirtualAlloc(NULL, sizeof(AQUA_MODULE), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, pApis->funcNtAllocateVirtualMemory);
	if (!pAquaModule) {
		if (pdwError)
			*pdwError = AQUA_ERROR_INVALID_ENV;
		return NULL;
	}

	pAquaModule->pApis = pApis;
	pAquaModule->bCallEntry = bCallEntry;
	pAquaModule->bLoadOk = FALSE;
	pAquaModule->dwErrorCode = AQUA_ERROR_OK;

	do {

		// Verify file format
		if (FALSE == RIsValidPEFormat(lpPeModuleBuffer)) {
			pAquaModule->dwErrorCode = AQUA_ERROR_BAD_PE_FORMAT;
			break;
		}

		// Map PE header and section table into memory
		if (FALSE == MapMemModuleSections(pAquaModule, lpPeModuleBuffer))
			break;

		// Relocate the module base
		if (FALSE == RelocateModuleBase(pAquaModule)) {
			UnmapMemModule(pAquaModule);
			break;
		}

		// Resolve the import table
		if (FALSE == ResolveImportTable(pAquaModule)) {
			UnmapMemModule(pAquaModule);
			break;
		}

		pAquaModule->dwCrc = GetCRC32(0, pAquaModule->lpBase, pAquaModule->dwSizeOfImage);

		// Correct the protect flag for all section pages
		if (FALSE == SetMemProtectStatus(pAquaModule)) {
			UnmapMemModule(pAquaModule);
			break;
		}

		if (FALSE == ExecuteTLSCallback(pAquaModule))
			break;

		if (bCallEntry) {
			if (FALSE == CallModuleEntry(pAquaModule, DLL_PROCESS_ATTACH)) {
				// failed to call entry point,
				// clean resource, return false
				UnmapMemModule(pAquaModule);
				break;
			}
		}

		if (pdwError)
			*pdwError = 0;
		return (HAQUAMODULE)pAquaModule;

	} while (0);

	if (pdwError)
		*pdwError = pAquaModule->dwErrorCode;
	FuncNtFreeVirtualMemory funcNtFreeVirtualMemory = pApis->funcNtFreeVirtualMemory;
	RVirtualFree(pAquaModule, 0, MEM_RELEASE, funcNtFreeVirtualMemory);
	RVirtualFree(pApis, 0, MEM_RELEASE, funcNtFreeVirtualMemory);

	return NULL;
}

VOID FreeMemModule(_In_ HAQUAMODULE hAquaModuleHandle) {
	PAQUA_MODULE pAquaModule = (PAQUA_MODULE)hAquaModuleHandle;
	pAquaModule->dwErrorCode = AQUA_ERROR_OK;

	if (pAquaModule->bCallEntry)
		CallModuleEntry(pAquaModule, DLL_PROCESS_DETACH);

	UnmapMemModule(pAquaModule);

	FuncNtFreeVirtualMemory funcNtFreeVirtualMemory = pAquaModule->pApis->funcNtFreeVirtualMemory;
	RVirtualFree(pAquaModule->pApis, 0, MEM_RELEASE, funcNtFreeVirtualMemory);
	RVirtualFree(pAquaModule, 0, MEM_RELEASE, funcNtFreeVirtualMemory);
}

FARPROC GetMemModuleProc(_In_ HAQUAMODULE hAquaModuleHandle, _In_ LPCSTR lpName) {
	PAQUA_MODULE pAquaModule = (PAQUA_MODULE)hAquaModuleHandle;

	return HIWORD(lpName) == 0 ? RGetProcAddress(pAquaModule->hModule, NULL, LOWORD(lpName)) : RGetProcAddress(pAquaModule->hModule, (LPSTR)lpName, 0);
}

void* aqua_memmove(void* dest, const void* src, size_t len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else
	{
		char* lasts = (char*)s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

void* aqua_memset(void* dest, int val, size_t len) {
	unsigned char* ptr = dest;
	while (len-- > 0)
		*ptr++ = (unsigned char)val;
	return dest;
}

wchar_t* aqua_strtowcs(wchar_t* d, const char* t, size_t len) {
	for (unsigned int i = 0; i < len; ++i)
		d[i] = t[i];
	return d;
}

int aqua_tolower(int c) {
	if (c >= 65 && c <= 90) {
		return c + 32;
	}
	return c;
}

int aqua_strcmp(const char* s1, const char* s2) {
	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);
	return (*(unsigned char*)s1 - *(unsigned char*)--s2);
}

size_t aqua_strlen(const char* str) {
	const char* s;

	for (s = str; *s; ++s)
		;
	return (s - str);
}

int aqua_wcsicmp(const wchar_t* cs, const wchar_t* ct) {
	while (aqua_tolower(*cs) == aqua_tolower(*ct))
	{
		if (*cs == 0)
			return 0;
		cs++;
		ct++;
	}
	return aqua_tolower(*cs) - aqua_tolower(*ct);
}

void AquaModuleHelperEnd() {
	return;
}

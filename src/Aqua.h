#ifndef _AQUA_H
#define _AQUA_H
#include "ntdll.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AQUA_ERROR_OK 0
#define AQUA_ERROR_BAD_PE_FORMAT 1
#define AQUA_ERROR_ALLOCATED_MEMORY_FAILED 2
#define AQUA_ERROR_INVALID_RELOCATION_BASE 3
#define AQUA_ERROR_IMPORT_MODULE_FAILED 4
#define AQUA_ERROR_PROTECT_SECTION_FAILED 5
#define AQUA_ERROR_INVALID_ENTRY_POINT 6
#define AQUA_ERROR_INVALID_ENV 0xff

	typedef enum _AQUAHELPER_METHOD {
		AHM_LOAD_MODULE,
		AHM_FREE_VOID,
		AHM_GETPROC_FARPROC
	}AMHELPER_METHOD;

	typedef void** HAQUAMODULE;

	typedef LPVOID(* FuncMemModuleHelper)(AMHELPER_METHOD, LPVOID, LPVOID, LPVOID);

	HAQUAMODULE LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD* pdwError);

	VOID FreeMemModule(_In_ HAQUAMODULE hAquaModuleHandle);

	FARPROC GetMemModuleProc(_In_ HAQUAMODULE hAquaModuleHandle, _In_ LPCSTR lpName);

#ifdef __cplusplus
}
#endif


#endif


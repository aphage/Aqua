#ifndef _NTDLL_H
#define _NTDLL_H
#include <phnt_windows.h>
#include <phnt.h>

typedef
NTSTATUS
(NTAPI* FuncLdrLoadDll)(
	_In_opt_ PWSTR DllPath,
	_In_opt_ PULONG DllCharacteristics,
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID* DllHandle
	);

typedef
NTSTATUS
(NTAPI* FuncLdrGetProcedureAddress)(
	_In_ PVOID DllHandle,
	_In_opt_ PANSI_STRING ProcedureName,
	_In_opt_ ULONG ProcedureNumber,
	_Out_ PVOID* ProcedureAddress
	);

typedef
NTSTATUS
(NTAPI* FuncNtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);

typedef
NTSTATUS
(NTAPI* FuncNtFreeVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG FreeType
	);

typedef
NTSTATUS
(NTAPI* FuncNtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);


typedef
BOOL
(WINAPI* FuncDllMain)(
	HMODULE,
	DWORD,
	LPVOID
	);
#endif
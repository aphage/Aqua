#include <Windows.h>
#include <stdio.h>

__declspec(dllexport) BOOL WINAPI AquaSuki(char* n);
__declspec(dllexport) void WINAPI Daregakawai(char* say, char* reply, size_t replySize);


__declspec(dllexport) BOOL WINAPI AquaSuki(char *n) {
	if (n == NULL)
		return FALSE;
	return !_stricmp("suki", n);
}
__declspec(dllexport) void WINAPI Daregakawai(char * say,char* reply,size_t replySize) {
	if (say == NULL) {
		strcpy_s(reply, replySize, "Isoide");
		return;
	}
	if (_stricmp("aqua", say) == 0) {
		strcpy_s(reply, replySize, "Watashi mo anatagasuki");
		return;
	}
	else {
		strcat_s(reply, replySize, say);
		strcat_s(reply, replySize, " Dare?");
		return;
	}
}


BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved){
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
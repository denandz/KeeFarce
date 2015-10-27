#pragma once
#include "stdafx.h"
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

// For exporting functions without name-mangling
#define DllExport extern "C" __declspec( dllexport )

// Our sole export for the time being
DllExport void LoadManagedProject(const wchar_t * managedDllLocation);

// Not exporting, so go ahead and name-mangle
ICLRRuntimeHost* StartCLR(LPCWSTR dotNetVersion);

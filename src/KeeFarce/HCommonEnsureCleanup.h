// Source code courtesy of http://www.gamedeception.net/forums/184-Windows-Internals

#pragma once
#ifndef HCOMMON__ENSURECLEANUP_H
#define HCOMMON__ENSURECLEANUP_H

// Windows API
#include <Windows.h>

// Hades namespace
namespace Hades
{
	// Data type representing the address of the object's cleanup function.
	// I used UINT_PTR so that this class works properly in 64-bit Windows.
	typedef VOID(WINAPI* PFNENSURECLEANUP)(UINT_PTR);

	// Each template instantiation requires a data type, address of cleanup 
	// function, and a value that indicates an invalid value.
	template<class TYPE, PFNENSURECLEANUP pfn, UINT_PTR tInvalid = NULL>
	class EnsureCleanup
	{
	public:
		// Default constructor assumes an invalid value (nothing to cleanup)
		EnsureCleanup()
		{
			m_t = tInvalid;
		}

		// This constructor sets the value to the specified value
		EnsureCleanup(TYPE t) : m_t((UINT_PTR)t)
		{ }

		// The destructor performs the cleanup.
		~EnsureCleanup()
		{
			Cleanup();
		}

		// Helper methods to tell if the value represents a valid object or not..
		BOOL IsValid() const
		{
			return(m_t != tInvalid);
		}
		BOOL IsInvalid() const
		{
			return(!IsValid());
		}

		// Re-assigning the object forces the current object to be cleaned-up.
		TYPE operator= (TYPE t)
		{
			Cleanup();
			m_t = (UINT_PTR)t;
			return(*this);
		}

		// Returns the value (supports both 32-bit and 64-bit Windows).
		operator TYPE() const
		{
			return (TYPE)m_t;
		}

		// Cleanup the object if the value represents a valid object
		void Cleanup()
		{
			if (IsValid())
			{
				// In 64-bit Windows, all parameters are 64-bits, 
				// so no casting is required
				pfn(m_t);                 // Close the object.
				m_t = tInvalid;     // We no longer represent a valid object.
			}
		}

	private:
		UINT_PTR m_t;                     // The member representing the object
	};

	// Macros to make it easier to declare instances of the template 
	// class for specific data types.

#define MakeCleanupClass(className, tData, pfnCleanup) \
        typedef EnsureCleanup<tData, (PFNENSURECLEANUP) pfnCleanup> className

#define MakeCleanupClassX(className, tData, pfnCleanup, tInvalid) \
        typedef EnsureCleanup<tData, (PFNENSURECLEANUP) pfnCleanup, \
        (INT_PTR) tInvalid> className

	// Instances of the template C++ class for common data types.
	MakeCleanupClass(EnsureCloseHandle, HANDLE, CloseHandle);
	MakeCleanupClass(EnsureLocalFree, HLOCAL, LocalFree);
	MakeCleanupClass(EnsureGlobalFree, HGLOBAL, GlobalFree);
	MakeCleanupClass(EnsureGlobalUnlock, LPVOID, GlobalUnlock);
	MakeCleanupClass(EnsureRegCloseKey, HKEY, RegCloseKey);
	MakeCleanupClass(EnsureCloseServiceHandle, SC_HANDLE, CloseServiceHandle);
	MakeCleanupClass(EnsureCloseWindowStation, HWINSTA, CloseWindowStation);
	MakeCleanupClass(EnsureCloseDesktop, HDESK, CloseDesktop);
	MakeCleanupClass(EnsureUnmapViewOfFile, PVOID, UnmapViewOfFile);
	MakeCleanupClass(EnsureFreeLibrary, HMODULE, FreeLibrary);
	MakeCleanupClass(EnsureRemoveVEH, PVOID, RemoveVectoredExceptionHandler);
	MakeCleanupClassX(EnsureCloseFile, HANDLE, CloseHandle, INVALID_HANDLE_VALUE);

	// Special class for releasing a reserved region.
	// Special class is required because VirtualFree requires 3 parameters
	class EnsureReleaseRegion
	{
	public:
		EnsureReleaseRegion(PVOID pv = NULL) : m_pv(pv)
		{ }

		~EnsureReleaseRegion()
		{
			Cleanup();
		}

		PVOID operator= (PVOID pv)
		{
			Cleanup();
			m_pv = pv;
			return(m_pv);
		}

		operator PVOID() const
		{
			return(m_pv);
		}

		void Cleanup()
		{
			if (m_pv != NULL)
			{
				VirtualFree(m_pv, 0, MEM_RELEASE);
				m_pv = NULL;
			}
		}

	private:
		PVOID m_pv;
	};

	// Special class for freeing a block from a heap
	// Special class is required because HeapFree requires 3 parameters
	class EnsureHeapFree
	{
	public:
		EnsureHeapFree(PVOID pv = NULL, HANDLE hHeap = GetProcessHeap())
			: m_pv(pv), m_hHeap(hHeap)
		{ }
		~EnsureHeapFree()
		{
			Cleanup();
		}

		PVOID operator= (PVOID pv)
		{
			Cleanup();
			m_pv = pv;
			return(m_pv);
		}

		operator PVOID() const
		{
			return(m_pv);
		}

		void Cleanup()
		{
			if (m_pv != NULL)
			{
				HeapFree(m_hHeap, 0, m_pv);
				m_pv = NULL;
			}
		}

	private:
		HANDLE m_hHeap;
		PVOID m_pv;
	};

	// Special class for releasing a remote reserved region.
	// Special class is required because VirtualFreeEx requires 4 parameters
	class EnsureReleaseRegionEx
	{
	public:
		EnsureReleaseRegionEx(PVOID pv = NULL, HANDLE proc = NULL) : m_pv(pv),
			m_proc(proc)
		{ }
		~EnsureReleaseRegionEx()
		{
			Cleanup();
		}

		PVOID operator= (PVOID pv)
		{
			Cleanup();
			m_pv = pv;
			return(m_pv);
		}

		operator PVOID() const
		{
			return(m_pv);
		}

		void Cleanup()
		{
			if (m_pv != NULL && m_proc != NULL)
			{
				VirtualFreeEx(m_proc, m_pv, 0, MEM_RELEASE);
				m_pv = NULL;
			}
		}

	private:
		PVOID m_pv;
		HANDLE m_proc;
	};

	// Special class for closing the clipboard.
	// Special class is required because no params are required.
	class EnsureCloseClipboard
	{
	public:
		EnsureCloseClipboard(BOOL Success) : m_Success(Success)
		{ }
		~EnsureCloseClipboard()
		{
			Cleanup();
		}

		BOOL operator= (BOOL Success)
		{
			Cleanup();
			m_Success = Success;
			return(m_Success);
		}

		operator BOOL() const
		{
			return(m_Success);
		}

		void Cleanup()
		{
			if (m_Success)
			{
				CloseClipboard();
				m_Success = FALSE;
			}
		}

	private:
		BOOL m_Success;
	};
}

#endif // HCOMMON__ENSURECLEANUP_H

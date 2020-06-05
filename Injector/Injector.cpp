#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "src/injdll.h"

int main(int argc, char **argv) {
#if 1
	wchar_t exe_path[MAX_PATH+1];
	wchar_t lib_path[MAX_PATH+1];
	STARTUPINFOW si = {0};
	PROCESS_INFORMATION pi = {0};
#ifdef _WIN64
	BOOLEAN isWow64 = FALSE;
#endif

	// Print usage.
	if (argc < 3) {
		fprintf(stderr, "Usage: inject EXE DLL\n");
		fprintf(stderr, "Inject a shared library into the address space of a binary executable.\n");
		return 1;
	}

	_snwprintf_s(lib_path, (MAX_PATH + 1) * sizeof(wchar_t), L"%S", argv[2]);
	if (GetFileAttributesW(lib_path) == INVALID_FILE_ATTRIBUTES) {
		fprintf(stderr, "Unable to locate library (%s).\n", argv[2]);
		return 1;
	}

	_snwprintf_s(exe_path, (MAX_PATH + 1) * sizeof(wchar_t), L"%S", argv[1]);
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcessW(NULL, exe_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "CreateProcess(\"%s\") failed; error code = 0x%08X\n", argv[1], GetLastError());
		return 1;
	}

#ifdef _WIN64
	ULONG_PTR peb32;
	if (!NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, ProcessWow64Information, &peb32, sizeof(ULONG_PTR), NULL))){
		return 1;
	}
	isWow64 = !!peb32;
#endif

#if 1
	// Disable pralelized dll loading
	// https://stackoverflow.com/questions/42789199/why-there-are-three-unexpected-worker-threads-when-a-win32-console-application-s/42789684
	//

	BYTE* pebAddress;
#ifdef _WIN64
	if (isWow64)
		pebAddress = (BYTE*)peb32;
	else
#endif
	{
		PROCESS_BASIC_INFORMATION basicInfo;
		if (!NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &basicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL))){
			return 1;
		}

		pebAddress = (BYTE*)basicInfo.PebBaseAddress;
	}

	unsigned long long LoaderThreadsOffset = 0;
#ifdef _WIN64
	if (!isWow64)
	{
		const int ProcessParameters_64 = 32; // FIELD_OFFSET(PEB, ProcessParameters); // 64 bit
		const int LoaderThreads_64 = 1036; // FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, LoaderThreads); // 64 bit

		unsigned long long ProcessParameters;
		if (!NT_SUCCESS(ReadProcessMemory(pi.hProcess, pebAddress + ProcessParameters_64, &ProcessParameters, sizeof(ProcessParameters), NULL))){
			return 1;
		}

		LoaderThreadsOffset = ProcessParameters + LoaderThreads_64;
	}
	else
#endif
	{
		const int ProcessParameters_32 = 16; // FIELD_OFFSET(PEB, ProcessParameters); // 32 bit
		const int LoaderThreads_32 = 672; // FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, LoaderThreads); // 32 bit

		unsigned long ProcessParameters;
		if (!NT_SUCCESS(ReadProcessMemory(pi.hProcess, pebAddress + ProcessParameters_32, &ProcessParameters, sizeof(ProcessParameters), NULL))){
			return 1;
		}

		LoaderThreadsOffset = ProcessParameters + LoaderThreads_32;
	}

	ULONG LoaderThreads;
	if (!NT_SUCCESS(ReadProcessMemory(pi.hProcess, (PVOID)LoaderThreadsOffset, &LoaderThreads, sizeof(LoaderThreads), NULL))){
		return 1;
	}
	LoaderThreads = 1; 
	if (!NT_SUCCESS(WriteProcessMemory(pi.hProcess, (PVOID)LoaderThreadsOffset, &LoaderThreads, sizeof(LoaderThreads), NULL))){
		return 1;
	}
#endif

	BOOL ret;
#ifdef BUILD_ARCH_X64
	if (!isWow64)
		ret = inject_x64(&pi, lib_path);
	else
#endif
		ret = inject_x86(&pi, lib_path);

	if (!ret) {
		fprintf(stderr, "inject failed, prcess terminated\n");
		TerminateProcess(pi.hProcess, -1);
		return 1;
	}
	
	if (ResumeThread(pi.hThread) == -1) {
		fprintf(stderr, "ResumeThread failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	CloseHandle(pi.hProcess);
#else
	int i, len;
	char *exe_path, *lib_path;
	void *page;
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};
	HANDLE hThread;

	// Print usage.
	if (argc < 2) {
		fprintf(stderr, "Usage: inject EXE [DLL...]\n");
		fprintf(stderr, "Inject an ordered list of shared libraries into the address space of a binary executable.\n");
		return 1;
	}

	// Execute the process in suspended mode.
	exe_path = argv[1];
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcessA(NULL, exe_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "CreateProcess(\"%s\") failed; error code = 0x%08X\n", exe_path, GetLastError());
		return 1;
	}

	// Allocate a page in memory for the arguments of LoadLibrary.
	page = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (page == NULL) {
		fprintf(stderr, "VirtualAllocEx failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Inject the ordered list of shared libraries into the address space of the
	// process.
	for (i = 2; i < argc; i++) {
		// Verify path length.
		lib_path = argv[i];
		len = (int)strlen(lib_path) + 1;
		if (len > MAX_PATH) {
			fprintf(stderr, "path length (%d) exceeds MAX_PATH (%d).\n", len, MAX_PATH);
			return 1;
		}
		if (GetFileAttributesA(lib_path) == INVALID_FILE_ATTRIBUTES) {
			fprintf(stderr, "unable to locate library (%s).\n", lib_path);
			return 1;
		}

		// Write library path to the page used for LoadLibrary arguments.
		if (WriteProcessMemory(pi.hProcess, page, lib_path, len, NULL) == 0) {
			fprintf(stderr, "WriteProcessMemory failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Inject the shared library into the address space of the process,
		// through a call to LoadLibrary.
		hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, page, 0, NULL);
		if (hThread == NULL) {
			fprintf(stderr, "CreateRemoteThread failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Wait for DllMain to return.
		if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
			fprintf(stderr, "WaitForSingleObject failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Cleanup.
		CloseHandle(hThread);
	}

	// Resume the execution of the process, once all libraries have been injected
	// into its address space.
	if (ResumeThread(pi.hThread) == -1) {
		fprintf(stderr, "ResumeThread failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Cleanup.
	CloseHandle(pi.hProcess);
	VirtualFreeEx(pi.hProcess, page, MAX_PATH, MEM_RELEASE);
#endif
	return 0;
}


/*
function used by MinHook

VirtualAlloc
VirtualQuery
VirtualFree

HeapCreate
HeapAlloc
HeapReAlloc
HeapFree
HeapDestroy

GetThreadContext
SetThreadContext

CreateToolhelp32Snapshot
Thread32First
Thread32Next

GetCurrentProcessId
GetCurrentThreadId

OpenThread
CloseHandle
SuspendThread
ResumeThread

VirtualProtect

FlushInstructionCache
InterlockedCompareExchange
InterlockedExchange

*/
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "..\MinHook_133_src\include\MinHook.h"
#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// Helper function for MH_CreateHookApi().
template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

//typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef int (WINAPI* GETSYSTEMMETRICS)(int nIndex);

// Pointer for calling original MessageBoxW.
//MESSAGEBOXW fpMessageBoxW = NULL;
GETSYSTEMMETRICS fpGetSystemMetrics = NULL;

// Detour function which overrides MessageBoxW.
int WINAPI DetourGetSystemMetrics(int nIndex)
{
	if (nIndex == SM_REMOTESESSION)
		return 0;
    return fpGetSystemMetrics(nIndex);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (MH_Initialize() != MH_OK) {
			MessageBoxW(NULL, L"Failed to initialize MinHook", L"HideTS", MB_OK);
			return TRUE;
		}

		if (MH_CreateHookApiEx(L"user32", "GetSystemMetrics", &DetourGetSystemMetrics, &fpGetSystemMetrics) != MH_OK)
		{
			MessageBoxW(NULL, L"Failed to create GetSystemMetrics hook", L"HideTS", MB_OK);
			return TRUE;
		}

		if (MH_EnableHook(&GetSystemMetrics) != MH_OK)
		{
			MessageBoxW(NULL, L"Failed to enable hook GetSystemMetrics", L"HideTS", MB_OK);
			return TRUE;
		}
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		if (MH_DisableHook(&GetSystemMetrics) != MH_OK)
		{
			MessageBoxW(NULL, L"Failed to disable hook GetSystemMetrics", L"HideTS", MB_OK);
			return TRUE;
		}

		if (MH_Uninitialize() != MH_OK) {
			MessageBoxW(NULL, L"Failed to uninitialize MinHook", L"HideTS", MB_OK);
			return TRUE;
		}
        break;
    }
    return TRUE;
}


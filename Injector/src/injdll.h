#ifndef INJDLL_H
#define INJDLL_H
#pragma once

#include <windows.h>

#if defined(_M_X64) || defined(_WIN64)
#define BUILD_ARCH_X64
#endif

#ifdef __cplusplus
extern "C" {
#endif

BOOL inject_x86(LPPROCESS_INFORMATION, const wchar_t*);
DWORD find_export_x86(const wchar_t*, const char*);

#ifdef BUILD_ARCH_X64
BOOL inject_x64(LPPROCESS_INFORMATION, const wchar_t*);
#endif

#ifdef __cplusplus
}
#endif

#endif /* INJDLL_H */

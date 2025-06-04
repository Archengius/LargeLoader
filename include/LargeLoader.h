/*
*   MIT License
*
*   Copyright (c) 2024 Nikita Zolotukhin
*
*   Permission is hereby granted, free of charge, to any person obtaining a copy
*   of this software and associated documentation files (the "Software"), to deal
*   in the Software without restriction, including without limitation the rights
*   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*   copies of the Software, and to permit persons to whom the Software is
*   furnished to do so, subject to the following conditions:
*
*   The above copyright notice and this permission notice shall be included in all
*   copies or substantial portions of the Software.
*
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*   SOFTWARE.
*/
#pragma once

#ifdef LL_EXPORTS
    #define LARGE_LOADER_API __declspec(dllexport)
#else
    #define LARGE_LOADER_API __declspec(dllimport)
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

/**
 * Resolves a function with the specified name for the given module using the Large Exports
 * Restrictions to the places in which this function can be safely called match the restrictions on GetProcAddress
 *
 * @param Module the module in which the export should be resolved. This must be a valid HMODULE handle.
 * @param ProcName name of the procedure as it appears in the export table. Note that ordinals are not supported here.
 * @return the address of the procedure or the data member, or nullptr if it cannot be found.
 */
EXTERN_C LARGE_LOADER_API FARPROC GetLargeProcAddress(HMODULE Module, LPCSTR ProcName);

/**
 * Scans the import directory table for the provided module and replaces GetProcAddress pointer with the pointer
 * to GetLargeProcAddress implementation. That allows modules that need to dynamically investigate exports of other modules
 * but that are not aware of Large Loader to successfully resolve exports in Large Loader-enabled modules
 *
 * @param Module the module for which GetProcAddress calls should be redirected to GetLargeProcAddress
 * @return true if GetProcAddress has been replaced for the module, or the module does not import GetProcAddress from Kernel32.dll
 */
EXTERN_C LARGE_LOADER_API BOOL RedirectGetProcAddressToLargeLoader(HMODULE Module);

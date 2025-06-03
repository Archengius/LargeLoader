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

#include "LargeLoader.h"

enum COFFLargeLoaderVersion {
    LARGE_LOADER_VERSION_INITIAL = 1,
    LARGE_LOADER_VERSION_ARM64EC_EXPORTAS = 2,
    LARGE_LOADER_VERSION_CIRCULAR_DEPS = 3,
};

// Internal definitions for Large Loader
// The types below are mirrored in llvm COFFLargeImport.h with the COFF prefix

enum LargeLoaderImportType {
    LARGE_LOADER_IMPORT_TYPE_INVALID = 0,
    LARGE_LOADER_IMPORT_TYPE_CODE = 1,
    LARGE_LOADER_IMPORT_TYPE_DATA = 2,
    LARGE_LOADER_IMPORT_TYPE_WILDCARD = 0xFF,
};

enum LargeLoaderHashAlgo {
    LARGE_LOADER_HASH_ALGO_CityHash64 = 0,
};

enum LargeLoaderImportFlags {
    LARGE_LOADER_IMPORT_FLAG_NONE = 0x0,
    LARGE_LOADER_IMPORT_FLAG_WILDCARD_LOOKUP_WIN32_EXPORT_DIRECTORY = 0x01,
    LARGE_LOADER_IMPORT_FLAG_SYNTHETIC = 0x02,
    LARGE_LOADER_IMPORT_FLAG_WEAK_DATA = 0x04,
};

struct LargeLoaderImport {
    WORD ExportSectionIndex;
    BYTE ImportKind;
    BYTE ImportFlags;
    DWORD NameLen;
    DWORD NameOffset;
    DWORD Pad;
};

struct LargeLoaderImportSectionHeader {
    WORD Version;
    WORD NumExportSections;
    DWORD NumImports;
    DWORD SingleImportSize;
    DWORD AddressTableOffset;
    DWORD ImportedExportSectionsOffset;
    DWORD ImportTableOffset;
    DWORD ImageFilenameOffset;
    DWORD ImageFilenameLength;
    DWORD AuxiliaryAddressTableOffset;
};

struct LargeLoaderExport {
    ULONGLONG ExportHash;
    WORD Pad[3];
    WORD ImportKind;
    DWORD NameLen;
    DWORD NameOffset;
};

struct LargeLoaderExportHashBucket {
    DWORD FirstExportIndex;
    DWORD NumExports;
};

struct LargeLoaderExportSectionHeader {
    WORD Version;
    WORD HashingAlgorithm;
    DWORD NumExportBuckets;
    DWORD NumExports;
    DWORD SingleExportSize;
    DWORD ExportRVATableOffset;
    DWORD ExportHashBucketTableOffset;
    DWORD ExportTableOffset;
    DWORD SectionHeaderRVA;
    DWORD ImageFilenameOffset;
    DWORD ImageFilenameLength;
    DWORD AuxExportRVATableOffset;
    LONG ImportSectionHeaderOffset;
    DWORD ImportSectionHeaderLength;
};

EXTERN_C LARGE_LOADER_API void __large_loader_register(HMODULE ImageBase, struct LargeLoaderExportSectionHeader* LargeExportSectionHeader); // NOLINT(*-reserved-identifier)
EXTERN_C LARGE_LOADER_API void __large_loader_unregister(HMODULE ImageBase); // NOLINT(*-reserved-identifier)
EXTERN_C LARGE_LOADER_API void __large_loader_link(HMODULE ImageBase, struct LargeLoaderImportSectionHeader* LargeImportSectionHeader); // NOLINT(*-reserved-identifier)

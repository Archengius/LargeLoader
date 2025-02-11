#include "LargeLoaderInternal.h"
#include "city.h"
#include <assert.h>
#include <stdio.h>

#ifndef NDEBUG
    _ACRTIMP void __cdecl _assert(const char*, const char*, unsigned); // NOLINT(*-reserved-identifier)
#endif

// Prints a message into the stdout, triggers an assert in debug builds, opens a user error message box and aborts the process
static void LogLinkErrorAndAbort(const char* format, ...)
{
    char errorMessageBuffer[500] = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(errorMessageBuffer, sizeof(errorMessageBuffer), format, args);
    va_end(args);

    fprintf(stderr, "[fatal] Large Loader: %s\n", errorMessageBuffer);
#ifndef NDEBUG
    _assert(errorMessageBuffer, __FILE__, __LINE__);
#endif
    MessageBoxA(NULL, errorMessageBuffer, "Large Loader: Fatal Link Error", MB_OK);
    abort();
}

// ImportNameLen includes the null terminator
static LPVOID FindLargeExportForLargeImportData(struct LargeLoaderExportSectionHeader* ExportsSectionHeader, const LPCSTR ImportName, const DWORD ImportNameLen, const BYTE ImportKind, BOOL IsVerboseLoggingEnabled)
{
    // Calculate the hash of the name based on the provided hashing algorithm
    ULONGLONG ImportNameHash = 0;
    if (ExportsSectionHeader->HashingAlgorithm == LARGE_LOADER_HASH_ALGO_CityHash64)
        ImportNameHash = CityHash64(ImportName, ImportNameLen);
    else
        LogLinkErrorAndAbort("Corrupt image: Unknown hashing algorithm ID %d when attempting to resolve import %s", ExportsSectionHeader->HashingAlgorithm, ImportName);

    // Resolve the hash bucket to which the hash maps, and the address of the first export entry in the bucket
    const struct LargeLoaderExportHashBucket* ExportHashBucketTable = (const struct LargeLoaderExportHashBucket*) ((BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportHashBucketTableOffset);
    const ULONGLONG HashBucketIndex = ImportNameHash % ExportsSectionHeader->NumExportBuckets;
    const struct LargeLoaderExportHashBucket HashBucket = ExportHashBucketTable[HashBucketIndex];

    BYTE* ExportImageBase = (BYTE*) ExportsSectionHeader - ExportsSectionHeader->SectionHeaderRVA;
    BYTE* ExportTable = (BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportTableOffset;
    UINT_PTR* ExportRVATable = (UINT_PTR*) ((BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportRVATableOffset);

    // Iterate over all exports in this hash bucket to attempt and find one matching this import
    for (DWORD LocalExportIndex = 0; LocalExportIndex < HashBucket.NumExports; LocalExportIndex++)
    {
        DWORD GlobalExportIndex = HashBucket.FirstExportIndex + LocalExportIndex;
        DWORD ExportStartOffset = ExportsSectionHeader->SingleExportSize * GlobalExportIndex;
        const struct LargeLoaderExport* LoaderExport = (struct LargeLoaderExport*) (ExportTable + ExportStartOffset);

        // Sanity check the name of the export
        LPCSTR ExportName = (LPCSTR) ((BYTE*) LoaderExport + LoaderExport->NameOffset);
        if (LoaderExport->NameLen >= 256 || LoaderExport->NameLen == 0 || ExportName[LoaderExport->NameLen] != 0)
            LogLinkErrorAndAbort("Corrupt image: Export name has invalid length or is not null terminated correctly for export index %d while resolving import %s", GlobalExportIndex, ImportName);

        // Log all the exports in the bucket if we are running with verbose logging until we match one
        if (IsVerboseLoggingEnabled && ExportName[LoaderExport->NameLen] == 0)
            printf("Large Loader: [Export %d Bucket %llu]: Export name is %s (kind: %d) with export hash %llu vs Import Hash %llu (kind: %d)\n",
                GlobalExportIndex, HashBucketIndex, ExportName, LoaderExport->ImportKind, LoaderExport->ExportHash, ImportNameHash, ImportKind);

        // Only consider exports that have the name hash match and the import kind matches exactly (or ImportKind is 0xFFFF, which stands for wildcard)
        if (LoaderExport->ExportHash == ImportNameHash && (ImportKind == 0xFFFF || LoaderExport->ImportKind == ImportKind))
        {
            // Check that the name of the export matches the name of the import now
            if (LoaderExport->NameLen == ImportNameLen && memcmp(ExportName, ImportName, LoaderExport->NameLen) == 0)
            {
                // Calculate the virtual address of the export by adding export image base to the export RVA
                return ExportImageBase + ExportRVATable[GlobalExportIndex];
            }
        }
    }
    // We have not found a matching export, so return NULL
    return NULL;
}

static LPVOID FindLargeExportForLargeImport(struct LargeLoaderExportSectionHeader* ExportsSection, const struct LargeLoaderImport* Import, BOOL IsVerboseLoggingEnabled)
{
    return FindLargeExportForLargeImportData(ExportsSection, (LPCSTR) ((BYTE*) Import + Import->NameOffset), Import->NameLen, Import->ImportKind, IsVerboseLoggingEnabled);
}

EXTERN_C LARGE_LOADER_API FARPROC GetLargeProcAddress(const HMODULE Module, const LPCSTR ProcName)
{
    // Resolve the address of the exports section first for the provided module
    struct LargeLoaderExportSectionHeader* ExportSection = (struct LargeLoaderExportSectionHeader*) GetProcAddress(Module, "__large_loader_exports_base");
    if (ExportSection == NULL)
    {
        return NULL;
    }
    // Cannot retrieve exports from the export library if the unknown version. But do not assert, just return null
    if (ExportSection->Version > CURRENT_LARGE_LOADER_VERSION)
    {
        return NULL;
    }

    // Resolve the export within the exports section
    const DWORD ProcNameLen = strlen(ProcName);
    // We do not know whenever the caller wants a data or code export, so match any
    return FindLargeExportForLargeImportData(ExportSection, ProcName, ProcNameLen, 0xFFFF, FALSE);
}

EXTERN_C LARGE_LOADER_API void __large_loader_link(HMODULE ImageBase, struct LargeLoaderImportSectionHeader* LargeImportSectionHeader)
{
    // Guard against versions newer than the current version, since we do not know how to parse them
    if (LargeImportSectionHeader->Version > CURRENT_LARGE_LOADER_VERSION)
        LogLinkErrorAndAbort("Corrupt image: Unknown header version %d for import section header of image %p. Maximum supported version is %d", LargeImportSectionHeader->Version, ImageBase, CURRENT_LARGE_LOADER_VERSION);

    // Sanity check the filename. It must have a null terminator at the length provided, and the length must be reasonable <256
    LPCSTR ImportImageFilename = (LPCSTR) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImageFilenameOffset);
    if (LargeImportSectionHeader->ImageFilenameLength >= 256 || LargeImportSectionHeader->ImageFilenameLength == 0 || ImportImageFilename[LargeImportSectionHeader->ImageFilenameLength] != 0)
        LogLinkErrorAndAbort("Corrupt image: Image filename has invalid length or is not terminated correctly for image at %p", ImageBase);

    LPVOID* ImportAddressTable = (LPVOID*) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->AddressTableOffset);
    struct LargeLoaderExportSectionHeader*** ImportedExportSections = (struct LargeLoaderExportSectionHeader***) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImportedExportSectionsOffset);
    BYTE* ImportTable = (BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImportTableOffset;

    // If we are verbose logging, print name of the import library and the number of imports
#if _DEBUG
    BOOL IsVerboseLoggingEnabled = TRUE;
#else
    BOOL IsVerboseLoggingEnabled = getenv("LARGE_LOADER_VERBOSE") != NULL;
#endif
    if (IsVerboseLoggingEnabled)
    {
        printf("Large Loader: Linking image %s version %d with %d imports from %d shared libraries: \n",
            ImportImageFilename, LargeImportSectionHeader->Version, LargeImportSectionHeader->NumImports, LargeImportSectionHeader->NumExportSections);

        for (DWORD LibraryIndex = 0; LibraryIndex < LargeImportSectionHeader->NumExportSections; LibraryIndex++)
        {
            struct LargeLoaderExportSectionHeader* ExportLibraryHeader = *ImportedExportSections[LibraryIndex];
            LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) ExportLibraryHeader + ExportLibraryHeader->ImageFilenameOffset);
            printf("Large Loader: - %s [version %d, hashing algo %d with %d buckets and %d exports]\n", ExportLibraryImageFilename,
                ExportLibraryHeader->Version, ExportLibraryHeader->HashingAlgorithm, ExportLibraryHeader->NumExportBuckets, ExportLibraryHeader->NumExports);
        }
    }

    // Allow writing to the import address table while we are resolving imports
    DWORD ImportAddressTableSize = sizeof(LPVOID) * LargeImportSectionHeader->NumImports;
    DWORD OldPageProtectionFlags = 0;
    BOOL MemoryProtectSucceeded = VirtualProtect(ImportAddressTable, ImportAddressTableSize, PAGE_READWRITE, &OldPageProtectionFlags);
    if (!MemoryProtectSucceeded)
        LogLinkErrorAndAbort("Failed to clear read-only protection status from the import address table of image %s", ImportImageFilename);

    // Resolve imports now
    for (DWORD ImportIndex = 0; ImportIndex < LargeImportSectionHeader->NumImports; ImportIndex++)
    {
        DWORD ImportStartOffset = LargeImportSectionHeader->SingleImportSize * ImportIndex;
        struct LargeLoaderImport* LoaderImport = (struct LargeLoaderImport*) (ImportTable + ImportStartOffset);

        // Sanity check the import. If the export section index is invalid, chances are the image is corrupted. Do not attempt to read the import name since it will most likely not be null terminated
        if (LoaderImport->ExportSectionIndex >= LargeImportSectionHeader->NumExportSections)
            LogLinkErrorAndAbort("Corrupted image: Export section index %d out of bounds (number of export sections: %d) for import ordinal {} of image {}",
                LoaderImport->ExportSectionIndex, LargeImportSectionHeader->NumExportSections, ImportIndex, ImportImageFilename);

        // Resolve the export section to which this import maps
        struct LargeLoaderExportSectionHeader* LibraryExportSectionHeader = *ImportedExportSections[LoaderImport->ExportSectionIndex];

        // Sanity check the export section header version. We cannot handle versions above our current version
        if (LibraryExportSectionHeader->Version > CURRENT_LARGE_LOADER_VERSION)
            LogLinkErrorAndAbort("Corrupt image: Unknown header version %d for export section header of library index %d of image %s. Maximum supported version is %d",
                LargeImportSectionHeader->Version, LoaderImport->ExportSectionIndex, ImportImageFilename, CURRENT_LARGE_LOADER_VERSION);
        // Sanity check the library filename. It must have a null terminator at the length provided, and the length must be reasonable <256
        LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) LibraryExportSectionHeader + LibraryExportSectionHeader->ImageFilenameOffset);
        if (LibraryExportSectionHeader->ImageFilenameLength >= 256 || LibraryExportSectionHeader->ImageFilenameLength == 0 || ExportLibraryImageFilename[LibraryExportSectionHeader->ImageFilenameLength] != 0)
            LogLinkErrorAndAbort("Corrupt image: Library filename has invalid length or is not terminated correctly for library index %d of image %s", LoaderImport->ExportSectionIndex, ImportImageFilename);

        // Make sure the import is null terminated and has a reasonable length
        LPCSTR ImportName = (LPCSTR) ((BYTE*) LoaderImport + LoaderImport->NameOffset);
        if (LoaderImport->NameLen >= 256 || LoaderImport->NameLen == 0 || ImportName[LoaderImport->NameLen] != 0)
            LogLinkErrorAndAbort("Corrupt image: Import name has invalid length or is not null terminated correctly for import index %d of image %s", ImportIndex, ImportImageFilename);

        // Resolve the export address now
        if (IsVerboseLoggingEnabled)
            printf("Large Loader: Linking import %s (kind: %d) from library %s\n", ImportName, LoaderImport->ImportKind, ExportLibraryImageFilename);
        LPVOID ResolvedExportAddress = FindLargeExportForLargeImport(LibraryExportSectionHeader, LoaderImport, IsVerboseLoggingEnabled);

        // Make sure we actually succeeded in resolving the address. Failure to do so results in an abort
        if (ResolvedExportAddress == NULL)
            LogLinkErrorAndAbort("Failed to find export for import %s of kind %d in shared library %s", ImportName, LoaderImport->ImportKind, ExportLibraryImageFilename);
        if (IsVerboseLoggingEnabled)
            printf("Large Loader: Linked import %s to export address %p\n", ImportName, ResolvedExportAddress);

        // Write the export address to the address table for this import
        ImportAddressTable[ImportIndex] = ResolvedExportAddress;
    }

    // Restore the original flags on the import address table page to disallow writing to it
    VirtualProtect(ImportAddressTable, ImportAddressTableSize, OldPageProtectionFlags, &OldPageProtectionFlags);
    if (IsVerboseLoggingEnabled)
        printf("Large Loader: Successfully linked image %s\n", ImportImageFilename);
}

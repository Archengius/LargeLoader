#include "LargeLoaderInternal.h"
#include "city.h"
#include <stdio.h>
#include <Winternl.h>

#define CURRENT_LARGE_LOADER_VERSION LARGE_LOADER_VERSION_CIRCULAR_DEPS
#define LINKER_PLACEHOLDER_ADDRESS_VALUE (LPVOID)1

#define LINKER_LOG_LEVEL_FATAL 0
#define LINKER_LOG_LEVEL_ERROR 1
#define LINKER_LOG_LEVEL_LOG 2
#define LINKER_LOG_LEVEL_VERBOSE 3
#define LINKER_LOG_LEVEL_VERY_VERBOSE 4

struct LargeLoaderModuleEntry
{
    HMODULE ModuleHandle;
    struct LargeLoaderExportSectionHeader* ExportSectionHeader;
    struct LargeLoaderModuleEntry* Prev;
    struct LargeLoaderModuleEntry* Next;
};

struct LargeLoaderImportResolutionResult
{
    LPVOID MainAddress; // always populated, on ARM64EC this is address into main IAT, which can point to X64 code or ARM64EC code
    LPVOID AuxiliaryAddress; // Only populated on ARM64EC if auxiliary export table has a symbol, otherwise NULL
};

static DWORD VerboseLoggingLevel = 0;
static SRWLOCK LoadedModulesListLock;
static struct LargeLoaderModuleEntry* LoadedModulesListHead;

// Basic implementation of RtlImageNtHeaderEx without exception handling and boundary checking
static PIMAGE_NT_HEADERS RtlImageNtHeaderEx(PVOID ImageBase)
{
    // Image must always start with a DOS header with DOS magic
    const PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) ImageBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Resolve the offset to the NT image headers directory from the DOS stub at offset 0x3C
    const INT32 NtHeaderOffset = *(PINT32) ((BYTE*) ImageBase + 0x3C);
    const PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS) ((BYTE*) ImageBase + NtHeaderOffset);

    // Image header must always start with PE image magic
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Optional header must always be present for images
    if (NtHeader->FileHeader.SizeOfOptionalHeader == 0)
        return NULL;

    // Optional header magic must match our native architecture. E.g. if we're compiled for WIN64 we must have a PE32+ image, and not PE image
    if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return NULL;
    return NtHeader;
}

EXTERN_C BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        // We do not need callbacks from the threading library when new threads are spawned
        DisableThreadLibraryCalls(instance);

        // Check if we want verbose logging or not
        const char* VerbosityLevelStr = getenv("LARGE_LOADER_VERBOSE");
        if (VerbosityLevelStr)
        {
            VerboseLoggingLevel = strtoul(VerbosityLevelStr, 0, 0);
        }
        else
        {
#if _DEBUG
            VerboseLoggingLevel = LINKER_LOG_LEVEL_LOG; // Enable logging by default in debug builds
#else
            VerboseLoggingLevel = LINKER_LOG_LEVEL_ERROR; // Only errors if env variable is not provided in release builds
#endif
        }
        // Initialize the loaded modules lock
        InitializeSRWLock(&LoadedModulesListLock);
        LoadedModulesListHead = NULL;
    }
    return TRUE;
}

static const char* LogLinkVerbosityToString(DWORD VerbosityLevel)
{
    switch (VerbosityLevel)
    {
        case LINKER_LOG_LEVEL_FATAL: return "Fatal";
        case LINKER_LOG_LEVEL_ERROR: return "Error";
        case LINKER_LOG_LEVEL_LOG: return "Log";
        case LINKER_LOG_LEVEL_VERBOSE: return "Verbose";
        case LINKER_LOG_LEVEL_VERY_VERBOSE: return "VeryVerbose";
        default: return "Unknown";
    }
}

static void LogLink(DWORD VerbosityLevel, const char* MessageFormat, ...)
{
    va_list Args;
    va_start(Args, MessageFormat);
    if (VerboseLoggingLevel >= VerbosityLevel || VerbosityLevel == LINKER_LOG_LEVEL_FATAL)
    {
        // Format the message provided to the function first
        char FormattedMessageBuffer[4096] = {0};
        vsnprintf(FormattedMessageBuffer, sizeof(FormattedMessageBuffer), MessageFormat, Args);

        // Create a log line from the formatted message and verbosity
        char LogLineMessageBuffer[4096] = {0};
        sprintf_s(LogLineMessageBuffer, sizeof(LogLineMessageBuffer), "LogLargeLoader: %s: %s\n",
            LogLinkVerbosityToString(VerbosityLevel), FormattedMessageBuffer);

        // We always print to debugger output feed
        OutputDebugStringA(LogLineMessageBuffer);

        // For fatal logs, we print to error output, show the dialog box, and immediately exit without running termination code
        // We do not run the termination code because link failure will most likely result in access violation if terminators
        // attempt to access symbols that failed to be resolved by the loader
        if (VerbosityLevel == LINKER_LOG_LEVEL_FATAL)
        {
            fprintf(stderr, "FATAL: %s", LogLineMessageBuffer);
            fflush(stderr);

            MessageBoxA(NULL, LogLineMessageBuffer, "Large Loader: Fatal Link Error", MB_OK);
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        // For error logs, we print to stderr and immediately flush it
        if (VerbosityLevel <= LINKER_LOG_LEVEL_ERROR)
        {
            fprintf(stderr, "%s", LogLineMessageBuffer);
            fflush(stderr);
        }
        else
        {
            // For all other logs, we just print to stdout
            fprintf(stdout, "%s", LogLineMessageBuffer);
            fflush(stdout);
        }
    }
    va_end(Args);
}

// Returns the index of the export in the export table matching the import name, or -1 if the export with the matching name was not found
static INT32 FindExportIndexFromNameTable(const HMODULE ImageBase,  const DWORD* ExportNameRVATable, const DWORD ExportNameTableSize, const LPCSTR ImportName, const DWORD ImportNameLen)
{
    DWORD StartIndexInclusive = 0;
    DWORD EndIndexExclusive = ExportNameTableSize;

    // Export name table is sorted lexically, so we do not need to perform a full search over the table - binary search can be used instead
    while (EndIndexExclusive > StartIndexInclusive)
    {
        const DWORD MiddleIndex = (StartIndexInclusive + EndIndexExclusive) / 2;
        const DWORD ExportNameRVA = ExportNameRVATable[MiddleIndex];
        const LPCSTR ExportName = (LPCSTR) ((BYTE*) ImageBase + ExportNameRVA);

        // We want to include the null terminator into the comparison, to ensure that the export name like "ExportNameFoo" does not match import "ExportName"
        // Import name is guaranteed to be null terminated by the linker.
        const INT32 NameComparisonResult = memcmp(ImportName, ExportName, ImportNameLen + 1);

        // If names are identical, this is the export index we have been looking for
        if (NameComparisonResult == 0)
            return (INT32)MiddleIndex;

        // Positive value means that ImportName appears after ExportName in lexicographical order. So our export, if it exists, is located past current MiddleIndex
        if (NameComparisonResult > 0)
            StartIndexInclusive = MiddleIndex + 1;
        // Negative value means that ImportName appears before ExportName in lexicographical order. So our export, if it exists, is located before current MiddleIndex
        else
            EndIndexExclusive = MiddleIndex;
    }
    // We did not find index for this import in this image export table, so return -1
    return -1;
}

// Pre-declaration. Returns address of the export resolved from the provided forwarder declaration.
static LPVOID ResolveWin32ExportForwarder(LPCSTR ForwarderDescriptor, const BOOL AllowLogging);

// Resolved Win32 export from the given image by its full name. Follows the forwarder chain.
static LPVOID ResolveWin32ExportFromImageBaseByName(const HMODULE ImageBase, const LPCSTR ExportName, const DWORD ExportNameLen, const BOOL AllowLogging)
{
    // Make sure we can retrieve the NT image header from this image, otherwise skip it
    const PIMAGE_NT_HEADERS ImageHeaderDirectory = RtlImageNtHeaderEx(ImageBase);
    const DWORD ExportDirectoryIndex = IMAGE_DIRECTORY_ENTRY_EXPORT;
    if (ImageHeaderDirectory == NULL || ImageHeaderDirectory->OptionalHeader.NumberOfRvaAndSizes <= ExportDirectoryIndex)
        return NULL;

    // Get directory entry for the export directory. The image only has the export table if the directory size is more than zero
    const PIMAGE_DATA_DIRECTORY ExportDataDirectoryEntry = &ImageHeaderDirectory->OptionalHeader.DataDirectory[ExportDirectoryIndex];
    if (ExportDataDirectoryEntry->Size == 0)
        return NULL;
    const PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((BYTE*) ImageBase + ExportDataDirectoryEntry->VirtualAddress);
    const DWORD* ExportNameRVATable = (PDWORD) ((BYTE*) ImageBase + ExportDirectory->AddressOfNames);
    const LPCSTR ExportLibraryName = (LPCSTR) ((BYTE*) ImageBase + ExportDirectory->Name);

    // Attempt to resolve the index of the import using the export name table. If we get a valid value, RVA can be recovered from functions table
    const INT32 ExportIndex = FindExportIndexFromNameTable(ImageBase, ExportNameRVATable, ExportDirectory->NumberOfNames, ExportName, ExportNameLen);
    if (ExportIndex < 0)
        return NULL;

    // Calculate the RVA of the forwarder or the export
    const WORD* ExportOrdinalTable = (PWORD) ((BYTE*) ImageBase + ExportDirectory->AddressOfNameOrdinals);
    const DWORD* ExportOrForwarderRVATable = (PDWORD) ((BYTE*) ImageBase + ExportDirectory->AddressOfFunctions);

    const WORD ExportOrdinal = ExportOrdinalTable[ExportIndex];
    const DWORD ExportOrForwarderRVA = ExportOrForwarderRVATable[ExportOrdinal];

    // If Export RVA is within the exports directory entry, this is actually a forwarder RVA pointing to the string describing the DLL name and the name of the export in that DLL to which this export is forwarded
    if (ExportOrForwarderRVA >= ExportDataDirectoryEntry->VirtualAddress && ExportOrForwarderRVA < ExportDataDirectoryEntry->VirtualAddress + ExportDataDirectoryEntry->Size)
    {
        const LPCSTR ForwarderName = (LPCSTR) ((BYTE*) ImageBase + ExportOrForwarderRVA);
        if (AllowLogging)
            LogLink(LINKER_LOG_LEVEL_VERBOSE, "Resolved Import %s from Win32 Export directory of loaded module %s to forwarder descriptor %s", ExportName, ExportLibraryName, ForwarderName);
        return ResolveWin32ExportForwarder(ForwarderName, AllowLogging);
    }

    // Otherwise, this is just a normal export RVA, so resolve it with image base to get an absolute export address
    const LPVOID ExportAbsoluteAddress = (BYTE*) ImageBase + ExportOrForwarderRVA;
    if (AllowLogging)
        LogLink(LINKER_LOG_LEVEL_VERBOSE, "Resolved Import %s from Win32 Export directory of loaded module %s to RVA %p", ExportName, ExportLibraryName, ExportAbsoluteAddress);
    return ExportAbsoluteAddress;
}

// Resolves Win32 export from the given image by its biased ordinal. Follows the forwarder chain.
static LPVOID ResolveWin32ExportFromImageBaseByOrdinal(const HMODULE ImageBase, const DWORD BiasedExportOrdinal, const BOOL AllowLogging)
{
    // Make sure we can retrieve the NT image header from this image, otherwise skip it
    const PIMAGE_NT_HEADERS ImageHeaderDirectory = RtlImageNtHeaderEx(ImageBase);
    const DWORD ExportDirectoryIndex = IMAGE_DIRECTORY_ENTRY_EXPORT;
    if (ImageHeaderDirectory == NULL || ImageHeaderDirectory->OptionalHeader.NumberOfRvaAndSizes <= ExportDirectoryIndex)
        return NULL;

    // Get directory entry for the export directory. The image only has the export table if the directory size is more than zero
    const PIMAGE_DATA_DIRECTORY ExportDataDirectoryEntry = &ImageHeaderDirectory->OptionalHeader.DataDirectory[ExportDirectoryIndex];
    if (ExportDataDirectoryEntry->Size == 0)
        return NULL;
    const PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((BYTE*) ImageBase + ExportDataDirectoryEntry->VirtualAddress);

    // Make sure that biased ordinal is valid, e.g. it's past or is a base ordinal and is below the total number of functions in the export directory
    if (BiasedExportOrdinal < ExportDirectory->Base || BiasedExportOrdinal - ExportDirectory->Base >= ExportDirectory->NumberOfFunctions)
        return NULL;

    const DWORD ExportOrdinal = BiasedExportOrdinal - ExportDirectory->Base;
    const DWORD* ExportOrForwarderRVATable = (PDWORD) ((BYTE*) ImageBase + ExportDirectory->AddressOfFunctions);
    const DWORD ExportOrForwarderRVA = ExportOrForwarderRVATable[ExportOrdinal];

    // If Export RVA is within the exports directory entry, this is actually a forwarder RVA pointing to the string describing the DLL name and the name of the export in that DLL to which this export is forwarded
    if (ExportOrForwarderRVA >= ExportDataDirectoryEntry->VirtualAddress && ExportOrForwarderRVA < ExportDataDirectoryEntry->VirtualAddress + ExportDataDirectoryEntry->Size)
    {
        const LPCSTR ForwarderName = (LPCSTR) ((BYTE*) ImageBase + ExportOrForwarderRVA);
        return ResolveWin32ExportForwarder(ForwarderName, AllowLogging);
    }
    // Otherwise, this is just a normal export RVA, so resolve it with image base to get an absolute export address
    const LPVOID ExportAbsoluteAddress = (BYTE*) ImageBase + ExportOrForwarderRVA;
    return ExportAbsoluteAddress;
}

// Parses the forwarder name into DLL name and ordinal or export name
static BOOL ParseForwarderDescriptor(const LPCSTR ForwarderDescriptor, LPCSTR* OutModuleBaseName, DWORD* OutModuleBaseNameLen, LPCSTR* OutImportName, DWORD* OutImportNameLen, INT32* OutImportOrdinal)
{
    // We must have a separator to form a valid forwarder descriptor
    const LPCSTR DllNameSeparator = strchr(ForwarderDescriptor, '.');
    if (DllNameSeparator == NULL)
        return FALSE;

    // Part before the separator is the module base name
    *OutModuleBaseName = ForwarderDescriptor;
    *OutModuleBaseNameLen = (DWORD) (DllNameSeparator - ForwarderDescriptor);

    // Part after the separator until the end of the string is the import (export) name
    const LPCSTR RawImportName = DllNameSeparator + 1;
    const DWORD RawImportNameLen = strlen(RawImportName);

    // This could also be a forwarder using the ordinal instead of the name. We can tell them apart by checking if the first character is a '#'
    if (RawImportNameLen > 0 && RawImportName[0] == '#')
    {
        *OutImportOrdinal = atoi(RawImportName + 1);
        *OutImportName = NULL;
        *OutImportNameLen = 0;
        return TRUE;
    }

    // This is not an ordinal import, but an ordinary forwarder to an import by name
    *OutImportOrdinal = -1;
    *OutImportName = RawImportName;
    *OutImportNameLen = RawImportNameLen;
    return TRUE;
}

// Returns true if the name of this module export directory matches the provided base module name, ignoring the extension
static BOOL MatchBaseModuleNameAgainstExportedModuleName(const HMODULE ImageBase, const LPCSTR BaseModuleName, const DWORD BaseModuleNameLen)
{
    // Make sure we can retrieve the NT image header from this image, otherwise skip it
    const PIMAGE_NT_HEADERS ImageHeaderDirectory = RtlImageNtHeaderEx(ImageBase);
    const DWORD ExportDirectoryIndex = IMAGE_DIRECTORY_ENTRY_EXPORT;
    if (ImageHeaderDirectory == NULL || ImageHeaderDirectory->OptionalHeader.NumberOfRvaAndSizes <= ExportDirectoryIndex)
        return FALSE;

    // Get directory entry for the export directory. The image only has the export table if the directory size is more than zero
    const PIMAGE_DATA_DIRECTORY ExportDataDirectoryEntry = &ImageHeaderDirectory->OptionalHeader.DataDirectory[ExportDirectoryIndex];
    if (ExportDataDirectoryEntry->Size == 0)
        return FALSE;
    const PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((BYTE*) ImageBase + ExportDataDirectoryEntry->VirtualAddress);
    const PCSTR ModuleName = (PCSTR) ((BYTE*) ImageBase + ExportDirectory->Name);

    // Base module name must match the name of this module from the start
    if (memcmp(ModuleName, BaseModuleName, BaseModuleNameLen) != 0)
        return FALSE;
    // Next character in the module name must be either a null terminator or a dot character signifying a file extension
    return ModuleName[BaseModuleNameLen] == '\0' || ModuleName[BaseModuleNameLen] == '.';
}

// Parses the forwarder name into DLL name and ordinal or export name, and attempts to resolve it using the currently loaded module list from the current process.
// Uses load order module linked list for iteration. The API is fairly stable and is used by quite a few applications.
// We cannot use Win32 Loader API GetProcAddress because during the link we are holding a loader lock.
static LPVOID ResolveWin32ExportForwarder(const LPCSTR ForwarderDescriptor, const BOOL AllowLogging)
{
    // Parse the descriptor into the relevant parts that we need to look up the DLL forwarded
    LPCSTR ModuleBaseName, ImportName;
    DWORD ModuleBaseNameLen, ImportNameLen;
    INT32 ImportOrdinal;
    if (!ParseForwarderDescriptor(ForwarderDescriptor, &ModuleBaseName, &ModuleBaseNameLen, &ImportName, &ImportNameLen, &ImportOrdinal))
        return NULL;

    const PPEB ProcessEnvBlock = NtCurrentTeb()->ProcessEnvironmentBlock;
    const PLIST_ENTRY InMemoryOrderListHead = &ProcessEnvBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY CurrentInMemoryOrderListEntry = InMemoryOrderListHead->Flink;

    // Iterate all loaded modules until we find one that contains the definition for the import
    while (CurrentInMemoryOrderListEntry != InMemoryOrderListHead)
    {
        const PLDR_DATA_TABLE_ENTRY LoaderDataTableEntry = CONTAINING_RECORD(CurrentInMemoryOrderListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const HMODULE ImageBase = LoaderDataTableEntry->DllBase;

        // Advance to the next linked list entry. We will finish iteration once we end up on the head entry again
        CurrentInMemoryOrderListEntry = LoaderDataTableEntry->InMemoryOrderLinks.Flink;

        // Since forwarder declaration only contains the base module name, and not a full module name, full module name can be either Module.dll or just Module
        if (MatchBaseModuleNameAgainstExportedModuleName(ImageBase, ModuleBaseName, ModuleBaseNameLen))
        {
            // If the import name is empty, we need to resolve the export by the ordinal
            if (ImportNameLen == 0)
            {
                if (AllowLogging)
                    LogLink(LINKER_LOG_LEVEL_VERBOSE, "Resolved forwarder into export by ordinal %d from module %s", ImportOrdinal, ModuleBaseName);
                return ResolveWin32ExportFromImageBaseByOrdinal(ImageBase, ImportOrdinal, AllowLogging);
            }
            // Otherwise, resolve the export by its full name
            if (AllowLogging)
                LogLink(LINKER_LOG_LEVEL_VERBOSE, "Resolved forwarder into export by name %s from module %s", ImportName, ModuleBaseName);
            return ResolveWin32ExportFromImageBaseByName(ImageBase, ImportName, ImportNameLen, AllowLogging);
        }
    }
    // We did not find a single module with the definition for this symbol. Return null
    return NULL;
}

// Attempts to resolve wildcard large import as a Win32 PE export in any DLL loaded in the process. Will follow forwarder chains as well.
// Uses load order module linked list for iteration. The API is fairly stable and is used by quite a few applications.
// We cannot use Win32 Loader API GetProcAddress because during the link we are holding a loader lock.
static LPVOID FindWin32ExportForLargeImportByName(const LPCSTR ImportName, const DWORD ImportNameLen, const BOOL AllowLogging)
{
    const PPEB ProcessEnvBlock = NtCurrentTeb()->ProcessEnvironmentBlock;
    const PLIST_ENTRY InMemoryOrderListHead = &ProcessEnvBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY CurrentInMemoryOrderListEntry = InMemoryOrderListHead->Flink;

    // Iterate all loaded modules until we find one that contains the definition for the import
    while (CurrentInMemoryOrderListEntry != InMemoryOrderListHead)
    {
        const PLDR_DATA_TABLE_ENTRY LoaderDataTableEntry = CONTAINING_RECORD(CurrentInMemoryOrderListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const HMODULE ImageBase = LoaderDataTableEntry->DllBase;

        // Advance to the next linked list entry. We will finish the iteration once we end up on the head entry again
        CurrentInMemoryOrderListEntry = LoaderDataTableEntry->InMemoryOrderLinks.Flink;

        // Attempt to resolve the symbol from the exports of this DLL, and return the result if succeeded
        const LPVOID PotentialResolutionResult = ResolveWin32ExportFromImageBaseByName(ImageBase, ImportName, ImportNameLen, AllowLogging);
        if (PotentialResolutionResult != NULL)
            return PotentialResolutionResult;
    }

    // We did not find a single module with the definition for this symbol. Return null
    return NULL;
}

// ImportNameLen includes the null terminator
static struct LargeLoaderImportResolutionResult FindLargeExportForLargeImportData(struct LargeLoaderExportSectionHeader* ExportsSectionHeader, const LPCSTR ImportName, const DWORD ImportNameLen, const BYTE ImportKind, const BOOL AllowLogging)
{
    // Calculate the hash of the name based on the provided hashing algorithm
    ULONGLONG ImportNameHash = 0;
    if (ExportsSectionHeader->HashingAlgorithm == LARGE_LOADER_HASH_ALGO_CityHash64)
        ImportNameHash = CityHash64(ImportName, ImportNameLen);
    else
        LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Unknown hashing algorithm ID %d when attempting to resolve import %s", ExportsSectionHeader->HashingAlgorithm, ImportName);

    // Resolve the hash bucket to which the hash maps, and the address of the first export entry in the bucket
    const struct LargeLoaderExportHashBucket* ExportHashBucketTable = (const struct LargeLoaderExportHashBucket*) ((BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportHashBucketTableOffset);
    const ULONGLONG HashBucketIndex = ImportNameHash % ExportsSectionHeader->NumExportBuckets;
    const struct LargeLoaderExportHashBucket HashBucket = ExportHashBucketTable[HashBucketIndex];

    BYTE* ExportImageBase = (BYTE*) ExportsSectionHeader - ExportsSectionHeader->SectionHeaderRVA;
    BYTE* ExportTable = (BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportTableOffset;
    UINT_PTR* ExportRVATable = (UINT_PTR*) ((BYTE*) ExportsSectionHeader + ExportsSectionHeader->ExportRVATableOffset);

    // Calculate the address of the auxiliary export RVA table if this image is of the newer version and has an auxiliary export table
    UINT_PTR* AuxiliaryExportRVATable = NULL;
    if (ExportsSectionHeader->Version >= LARGE_LOADER_VERSION_ARM64EC_EXPORTAS && ExportsSectionHeader->AuxExportRVATableOffset != 0)
        AuxiliaryExportRVATable = (UINT_PTR*) ((BYTE*) ExportsSectionHeader + ExportsSectionHeader->AuxExportRVATableOffset);

    // Iterate over all exports in this hash bucket to attempt and find one matching this import
    for (DWORD LocalExportIndex = 0; LocalExportIndex < HashBucket.NumExports; LocalExportIndex++)
    {
        DWORD GlobalExportIndex = HashBucket.FirstExportIndex + LocalExportIndex;
        DWORD ExportStartOffset = ExportsSectionHeader->SingleExportSize * GlobalExportIndex;
        const struct LargeLoaderExport* LoaderExport = (struct LargeLoaderExport*) (ExportTable + ExportStartOffset);

        // Sanity check the name of the export
        LPCSTR ExportName = (LPCSTR) ((BYTE*) LoaderExport + LoaderExport->NameOffset);
        if (LoaderExport->NameLen > 1024 || LoaderExport->NameLen == 0 || ExportName[LoaderExport->NameLen] != 0)
            LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Export name has invalid length or is not null terminated correctly for export index %d while resolving import %s NameLen: %d",
                GlobalExportIndex, ImportName, LoaderExport->NameLen);

        // Log all the exports in the bucket if we are running with verbose logging until we match one
        if (AllowLogging)
        {
            // Only do this if allow logging is true since this function can be called through GetLargeProcAddress, for which we do not want to do any logging
            LogLink(LINKER_LOG_LEVEL_VERY_VERBOSE, "[Export %d Bucket %llu]: Export name is %s (kind: %d) with export hash %llu vs Import Hash %llu (kind: %d)",
               GlobalExportIndex, HashBucketIndex, ExportName, LoaderExport->ImportKind, LoaderExport->ExportHash, ImportNameHash, ImportKind);
        }

        // Only consider exports that have the name hash match and the import kind matches exactly (or ImportKind is 0xFFFF, which stands for wildcard)
        if (LoaderExport->ExportHash == ImportNameHash && (ImportKind == LARGE_LOADER_IMPORT_TYPE_WILDCARD || LoaderExport->ImportKind == ImportKind))
        {
            // Check that the name of the export matches the name of the import now
            if (LoaderExport->NameLen == ImportNameLen && memcmp(ExportName, ImportName, LoaderExport->NameLen) == 0)
            {
                // Calculate the virtual address of the export by adding export image base to the export RVA
                struct LargeLoaderImportResolutionResult ResolutionResult;
                ResolutionResult.MainAddress = ExportImageBase + ExportRVATable[GlobalExportIndex];
                // Auxiliary address is only available if there is an auxiliary RVA table for this image
                ResolutionResult.AuxiliaryAddress = AuxiliaryExportRVATable ? ExportImageBase + AuxiliaryExportRVATable[GlobalExportIndex] : NULL;

                // Set the auxiliary export address to the main address if this export represents data, and the image has no auxiliary export table. On ARM64EC, data is shared by both ARM64EC code and X64 code
                // Technically we should never end up referencing data through auxiliary IAT, but this is possible when import does not know if it refers to data or to code,
                // which is a case when linking with auto wildcard imports enabled
                if (!ResolutionResult.AuxiliaryAddress && ResolutionResult.MainAddress && LoaderExport->ImportKind == LARGE_LOADER_IMPORT_TYPE_DATA)
                    ResolutionResult.AuxiliaryAddress = ResolutionResult.MainAddress;

                return ResolutionResult;
            }
        }
    }

    // We have not found a matching export, so return NULL
    struct LargeLoaderImportResolutionResult NullResolutionResult;
    NullResolutionResult.MainAddress = NULL;
    NullResolutionResult.AuxiliaryAddress = NULL;
    return NullResolutionResult;
}

static struct LargeLoaderImportResolutionResult FindLargeExportForLargeImport(struct LargeLoaderExportSectionHeader* ExportsSection, const struct LargeLoaderImport* Import, BOOL AllowLogging) {
    return FindLargeExportForLargeImportData(ExportsSection, (LPCSTR) ((BYTE*) Import + Import->NameOffset), Import->NameLen, Import->ImportKind, AllowLogging);
}

static struct LargeLoaderImportResolutionResult ResolveFullyQualifiedImportChecked(struct LargeLoaderImportSectionHeader* LargeImportSectionHeader, struct LargeLoaderImport* LoaderImport)
{
    struct LargeLoaderExportSectionHeader*** ImportedExportSections = (struct LargeLoaderExportSectionHeader***) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImportedExportSectionsOffset);
    const LPCSTR ImportImageFilename = (LPCSTR) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImageFilenameOffset);
    const LPCSTR ImportName = (LPCSTR) ((BYTE*) LoaderImport + LoaderImport->NameOffset);

    // Resolve the export section to which this import maps
    struct LargeLoaderExportSectionHeader* LibraryExportSectionHeader = *ImportedExportSections[LoaderImport->ExportSectionIndex];
    const LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) LibraryExportSectionHeader + LibraryExportSectionHeader->ImageFilenameOffset);

    // Resolve the export address now
    LogLink(LINKER_LOG_LEVEL_VERBOSE, "Linking import %s (kind: %d) from library %s", ImportName, LoaderImport->ImportKind, ExportLibraryImageFilename);
    struct LargeLoaderImportResolutionResult ResolvedExportAddress = FindLargeExportForLargeImport(LibraryExportSectionHeader, LoaderImport, TRUE);

    if (ResolvedExportAddress.MainAddress == NULL)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Failed to find export for import %s of kind %d in shared library %s (requested by library %s)", ImportName, LoaderImport->ImportKind, ExportLibraryImageFilename, ImportImageFilename);
    return ResolvedExportAddress;
}

static struct LargeLoaderImportResolutionResult ResolveWildcardImportChecked(struct LargeLoaderImportSectionHeader* LargeImportSectionHeader, struct LargeLoaderImport* LoaderImport)
{
    const LPCSTR ImportImageFilename = (LPCSTR) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImageFilenameOffset);
    const LPCSTR ImportName = (LPCSTR) ((BYTE*) LoaderImport + LoaderImport->NameOffset);

    // Acquire the lock and attempt to look up the import in any loaded dynamic library
    struct LargeLoaderImportResolutionResult ResolvedExportAddress;
    ResolvedExportAddress.MainAddress = NULL;
    ResolvedExportAddress.AuxiliaryAddress = NULL;

    {
        AcquireSRWLockShared(&LoadedModulesListLock);
        const struct LargeLoaderModuleEntry* Current = LoadedModulesListHead;
        while (Current != NULL)
        {
            struct LargeLoaderExportSectionHeader* LibraryExportSectionHeader = Current->ExportSectionHeader;
            const LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) LibraryExportSectionHeader + LibraryExportSectionHeader->ImageFilenameOffset);

            // Attempt to find the import definition inside of this library
            LogLink(LINKER_LOG_LEVEL_VERBOSE, "Attempting to link wildcard import %s (kind: %d) to library %s", ImportName, LoaderImport->ImportKind, ExportLibraryImageFilename);
            ResolvedExportAddress = FindLargeExportForLargeImport(LibraryExportSectionHeader, LoaderImport, TRUE);
            if (ResolvedExportAddress.MainAddress != NULL)
                break;
            Current = Current->Next;
        }
        ReleaseSRWLockShared(&LoadedModulesListLock);
    }

    // Attempt to resolve the wildcard import using the Win32 export directory if we are asked to do it
    if ((LoaderImport->ImportFlags & LARGE_LOADER_IMPORT_FLAG_WILDCARD_LOOKUP_WIN32_EXPORT_DIRECTORY) != 0)
    {
        LogLink(LINKER_LOG_LEVEL_VERY_VERBOSE, "Attempting to link wildcard import %s (kind: %d) using Win32 export directory of loaded modules", ImportName, LoaderImport->ImportKind);
        LPVOID MainExportAddress = FindWin32ExportForLargeImportByName(ImportName, LoaderImport->NameLen, TRUE);
        ResolvedExportAddress.MainAddress = MainExportAddress;
        ResolvedExportAddress.AuxiliaryAddress = NULL;

        // If this import type is data, or it is a wildcard import that is suspected to be data (weak_data flag), set the auxiliary address to the main address
        // Even if the target turns out to be code if this is a weak data hint, weak data flag implies that the caller only performs indirect calls through the function pointer,
        // which is correctly handled under ARM64EC even if it points to ARM64EC code and not to the native code
        if (ResolvedExportAddress.MainAddress && (LoaderImport->ImportKind == LARGE_LOADER_IMPORT_TYPE_DATA || (LoaderImport->ImportFlags & LARGE_LOADER_IMPORT_FLAG_WEAK_DATA) != 0))
            ResolvedExportAddress.AuxiliaryAddress = ResolvedExportAddress.MainAddress;
    }

    // Check that we have actually resolved the address
    if (ResolvedExportAddress.MainAddress == NULL)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Failed to link wildcard import %s of kind %d in any currently loaded shared library (requested by library %s)", ImportName, LoaderImport->ImportKind, ImportImageFilename);
    return ResolvedExportAddress;
}

EXTERN_C LARGE_LOADER_API FARPROC GetLargeProcAddress(const HMODULE Module, const LPCSTR ProcName)
{
    // Resolve the address of the exports section first for the provided module
    struct LargeLoaderExportSectionHeader* ExportSection = (struct LargeLoaderExportSectionHeader*) GetProcAddress(Module, "__large_loader_export_directory");
    if (ExportSection == NULL)
    {
        // Assume this is not a Large Loader enabled module and forward the request to the dynamic linker
        return GetProcAddress(Module, ProcName);
    }
    // Cannot retrieve exports from the export library if the unknown version. But do not assert, just return null
    if (ExportSection->Version > CURRENT_LARGE_LOADER_VERSION)
    {
        return NULL;
    }

    // Resolve the export within the exports section
    const DWORD ProcNameLen = strlen(ProcName);
    // We do not know whenever the caller wants a data or code export, so match any
    struct LargeLoaderImportResolutionResult Result = FindLargeExportForLargeImportData(ExportSection, ProcName, ProcNameLen, LARGE_LOADER_IMPORT_TYPE_WILDCARD, FALSE);

    // We also do not know if the caller is a native ARM64EC caller or emulated X64 code under ARM64EC, so return the main export address, which will always be set
    // native ARM64EC will never issue indirect calls into unknown addresses without routing them through __os_arm64x_check_icall, so returning X64 address is safe here
    return Result.MainAddress;
}

// Redirects import of GetProcAddress from Kernel32.dll to GetLargeProcAddress to make the code using GetProcAddress API compatible with Large Loader without recompilation
static BOOL RedirectGetProcAddressToLargeInternal(const HMODULE ImageBase, const LPCSTR ImageFilename, BOOL AllowLogging)
{
    const PIMAGE_NT_HEADERS NtImageHeaders = RtlImageNtHeaderEx(ImageBase);
    const IMAGE_DATA_DIRECTORY ImportDataDirEntry = NtImageHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectoryTable = (PIMAGE_IMPORT_DESCRIPTOR) ((BYTE*)ImageBase + ImportDataDirEntry.VirtualAddress);

    // Iterate import directory entries until we reach the null terminator (characteristics will be 0 for it)
    for (ULONG ImportTableIndex = 0; ImportDirectoryTable[ImportTableIndex].Characteristics != 0; ImportTableIndex++)
    {
        const LPCSTR ImportedDllName = (LPCSTR) ((BYTE*)ImageBase + ImportDirectoryTable[ImportTableIndex].Name);
        if (_stricmp(ImportedDllName, "Kernel32.dll") == 0)
        {
            const UINT_PTR* ImportDescriptorTable = (UINT_PTR*) ((BYTE*)ImageBase + ImportDirectoryTable[ImportTableIndex].OriginalFirstThunk);
            PVOID* BoundImportAddressTable = (PVOID*) ((BYTE*)ImageBase + ImportDirectoryTable[ImportTableIndex].FirstThunk);

            // Iterate import descriptor entries until we reach the null terminator
            for (ULONG ImportIndex = 0; ImportDescriptorTable[ImportIndex] != 0; ImportIndex++)
            {
                // Not interested in imports that are bound by the ordinal
                if (!IMAGE_SNAP_BY_ORDINAL(ImportDescriptorTable[ImportIndex]))
                {
                    const PIMAGE_IMPORT_BY_NAME ImportedSymbolName = (PIMAGE_IMPORT_BY_NAME) ((BYTE*)ImageBase + ImportDescriptorTable[ImportIndex]);
                    if (_stricmp(ImportedSymbolName->Name, "GetProcAddress") == 0 && BoundImportAddressTable[ImportIndex] != (PVOID) &GetLargeProcAddress)
                    {
                        // Remove protection from the memory page so we can write to the import address
                        DWORD OldPageProtectionFlags = 0;
                        const BOOL MemoryProtectSucceeded = VirtualProtect(&BoundImportAddressTable[ImportIndex], sizeof(PVOID), PAGE_READWRITE, &OldPageProtectionFlags);
                        if (!MemoryProtectSucceeded)
                        {
                            // Do not crash if logging is not enabled, e.g. this has been called externally through the Large Loader API
                            if (AllowLogging)
                                LogLink(LINKER_LOG_LEVEL_FATAL, "Failed to clear read-only status for GetProcAddress import entry for image %s", ImageFilename);
                            return FALSE;
                        }

                        // Update the pointer to point to our implementation that falls back to GetProcAddress if large loader is not used for module
                        BoundImportAddressTable[ImportIndex] = (PVOID) &GetLargeProcAddress;
                        // Logging is disabled if this function has been called externally
                        if (AllowLogging)
                            LogLink(LINKER_LOG_LEVEL_VERBOSE, "Redirected GetProcAddress to GetLargeProcAddress for image %s", ImageFilename);

                        // Restore the protection flags to the previous value
                        VirtualProtect(&BoundImportAddressTable[ImportIndex], sizeof(PVOID), OldPageProtectionFlags, &OldPageProtectionFlags);
                        return TRUE;
                    }
                }
            }
        }
    }
    // Even if we did not find GetProcAddress in the import table, this function succeeds
    return TRUE;
}

EXTERN_C LARGE_LOADER_API BOOL RedirectGetProcAddressToLargeLoader(HMODULE Module)
{
    char ModuleFilenameBuffer[4096] = {0};
    GetModuleFileNameA(Module, ModuleFilenameBuffer, sizeof(ModuleFilenameBuffer));
    return RedirectGetProcAddressToLargeInternal(Module, ModuleFilenameBuffer, FALSE);
}

EXTERN_C LARGE_LOADER_API void __large_loader_register(const HMODULE ImageBase, struct LargeLoaderExportSectionHeader* LargeExportSectionHeader)
{
    const LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) LargeExportSectionHeader + LargeExportSectionHeader->ImageFilenameOffset);

    // Sanity check the export section header version. We cannot handle versions above our current version
    if (LargeExportSectionHeader->Version > CURRENT_LARGE_LOADER_VERSION)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Unknown header version %d for export section header of library at %p. Maximum supported version is %d", LargeExportSectionHeader->Version, ImageBase, CURRENT_LARGE_LOADER_VERSION);

    // Sanity check the library filename. It must have a null terminator at the length provided, and the length must be reasonable <256
    if (LargeExportSectionHeader->ImageFilenameLength >= 256 || LargeExportSectionHeader->ImageFilenameLength == 0 || ExportLibraryImageFilename[LargeExportSectionHeader->ImageFilenameLength] != 0)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Library filename has invalid length or is not terminated correctly for library at %p", ImageBase);

    // Redirect GetLargeProcAddress for the image to our implementation that can handle large exports
    RedirectGetProcAddressToLargeInternal(ImageBase, ExportLibraryImageFilename, TRUE);

    // Create a new module list entry for this module
    struct LargeLoaderModuleEntry* NewModuleEntry = malloc(sizeof(struct LargeLoaderModuleEntry));
    memset(NewModuleEntry, 0, sizeof(struct LargeLoaderModuleEntry));
    NewModuleEntry->ModuleHandle = ImageBase;
    NewModuleEntry->ExportSectionHeader = LargeExportSectionHeader;

    // Append a new entry to the end of the loaded modules list. We need to be holding the loader lock for this
    {
        AcquireSRWLockExclusive(&LoadedModulesListLock);
        if (LoadedModulesListHead != NULL)
        {
            LoadedModulesListHead->Next = NewModuleEntry;
            NewModuleEntry->Prev = LoadedModulesListHead;
        } else
        {
            LoadedModulesListHead = NewModuleEntry;
        }
        ReleaseSRWLockExclusive(&LoadedModulesListLock);
    }
    // Notify that we have loaded a new library
    LogLink(LINKER_LOG_LEVEL_LOG, "Registered large library %s in the loaded module list lookup", ExportLibraryImageFilename);
}

EXTERN_C LARGE_LOADER_API void __large_loader_unregister(HMODULE ImageBase)
{
    // Remove the library from the loader list. We need to be holding the loader lock for this
    AcquireSRWLockExclusive(&LoadedModulesListLock);
    struct LargeLoaderModuleEntry* Current = LoadedModulesListHead;
    while (Current != NULL)
    {
        // Skip this module if this does not match our image base
        if (Current->ModuleHandle != ImageBase)
            continue;

        // Replace the reference to this element on the previous element with the next element, or replace the head of the list if this is the first element
        if (Current->Prev != NULL)
            Current->Prev->Next = Current->Next;
        else
            LoadedModulesListHead = Current->Next;

        // Point the next element after this element at the element before this element
        if (Current->Next != NULL)
            Current->Next->Prev = Current->Prev;

        // Free the memory allocated for this module entry
        free(Current);
        break;
    }
    ReleaseSRWLockExclusive(&LoadedModulesListLock);
}

EXTERN_C LARGE_LOADER_API void __large_loader_link(HMODULE ImageBase, struct LargeLoaderImportSectionHeader* LargeImportSectionHeader)
{
    // Guard against versions newer than the current version, since we do not know how to parse them
    if (LargeImportSectionHeader->Version > CURRENT_LARGE_LOADER_VERSION)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Unknown header version %d for import section header of image %p. Maximum supported version is %d", LargeImportSectionHeader->Version, ImageBase, CURRENT_LARGE_LOADER_VERSION);

    // Sanity check the filename. It must have a null terminator at the length provided, and the length must be reasonable <256
    LPCSTR ImportImageFilename = (LPCSTR) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImageFilenameOffset);
    if (LargeImportSectionHeader->ImageFilenameLength >= 256 || LargeImportSectionHeader->ImageFilenameLength == 0 || ImportImageFilename[LargeImportSectionHeader->ImageFilenameLength] != 0)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Image filename has invalid length or is not terminated correctly for image at %p", ImageBase);

    LPVOID* ImportAddressTable = (LPVOID*) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->AddressTableOffset);
    struct LargeLoaderExportSectionHeader*** ImportedExportSections = (struct LargeLoaderExportSectionHeader***) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImportedExportSectionsOffset);
    BYTE* ImportTable = (BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->ImportTableOffset;

    // Redirect GetLargeProcAddress for the image to our implementation that can handle large exports
    RedirectGetProcAddressToLargeInternal(ImageBase, ImportImageFilename, TRUE);

    // Skip linking images that have zero imports. In such cases the linker should not generate the large imports section at all
    if (LargeImportSectionHeader->NumImports == 0)
    {
        LogLink(LINKER_LOG_LEVEL_VERBOSE, "Skipping linking image %s because it has no imports", ImportImageFilename);
        return;
    }
    // If first entry in the address table is not zero, we have already linked this image, or are presently in the process of linking it (in case of circular dependencies)
    if (ImportAddressTable[0] != 0)
    {
        // If first import is set to the placeholder address value, we are in the process of linking images with cyclic dependencies,
        // and this image is already on the link stack and as such will be linked later
        if (ImportAddressTable[0] == LINKER_PLACEHOLDER_ADDRESS_VALUE)
            LogLink(LINKER_LOG_LEVEL_VERBOSE, "Discarding image %s link request because it is already on the cyclic dependency resolution stack", ImportImageFilename);
        else
            LogLink(LINKER_LOG_LEVEL_VERBOSE, "Discarding image %s link request because it has already been linked", ImportImageFilename);
        return;
    }

    // Calculate the auxiliary import table address for ARM64EC
    LPVOID* AuxiliaryImportAddressTable = NULL;
    if (LargeImportSectionHeader->Version >= LARGE_LOADER_VERSION_ARM64EC_EXPORTAS && LargeImportSectionHeader->AuxiliaryAddressTableOffset != 0)
        AuxiliaryImportAddressTable = (LPVOID*) ((BYTE*) LargeImportSectionHeader + LargeImportSectionHeader->AuxiliaryAddressTableOffset);

    // Log additional information about the library being linked
    LogLink(LINKER_LOG_LEVEL_LOG, "Linking image %s version %d with %d imports from %d shared libraries",
        ImportImageFilename, LargeImportSectionHeader->Version, LargeImportSectionHeader->NumImports, LargeImportSectionHeader->NumExportSections);

    // Allow writing to the import address table while we are resolving imports
    DWORD ImportAddressTableSize = sizeof(LPVOID) * LargeImportSectionHeader->NumImports;
    DWORD OldPageProtectionFlags = 0;
    BOOL MemoryProtectSucceeded = VirtualProtect(ImportAddressTable, ImportAddressTableSize, PAGE_READWRITE, &OldPageProtectionFlags);
    if (!MemoryProtectSucceeded)
        LogLink(LINKER_LOG_LEVEL_FATAL, "Failed to clear read-only protection status from the import address table of image %s", ImportImageFilename);

    // Now that we can write to the import address table, set the first entry to the placeholder address value,
    // so when we are processing cyclic dependencies, we will not attempt to link this image again when it is already on the link stack
    ImportAddressTable[0] = LINKER_PLACEHOLDER_ADDRESS_VALUE;

    // Validate the export sections referenced by this library before we attempt to work with them. In case of cyclic dependencies,
    // this might also cause the dependency images to be linked immediately without waiting for their normal DllMain execution
    for (DWORD LibraryIndex = 0; LibraryIndex < LargeImportSectionHeader->NumExportSections; LibraryIndex++)
    {
        struct LargeLoaderExportSectionHeader* ExportLibraryHeader = *ImportedExportSections[LibraryIndex];
        const HMODULE ExportLibraryImageBase = (HMODULE) ((BYTE*) ExportLibraryHeader - ExportLibraryHeader->SectionHeaderRVA);
        const LPCSTR ExportLibraryImageFilename = (LPCSTR) ((BYTE*) ExportLibraryHeader + ExportLibraryHeader->ImageFilenameOffset);

        // Sanity check the export section header version. We cannot handle versions above our current version
        if (ExportLibraryHeader->Version > CURRENT_LARGE_LOADER_VERSION)
        {
            LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Unknown header version %d for export section header of library index %d of image %s. Maximum supported version is %d",
                LargeImportSectionHeader->Version, LibraryIndex, ImportImageFilename, CURRENT_LARGE_LOADER_VERSION);
        }
        // Sanity check the library filename. It must have a null terminator at the length provided, and the length must be reasonable <256
        if (ExportLibraryHeader->ImageFilenameLength >= 256 || ExportLibraryHeader->ImageFilenameLength == 0 || ExportLibraryImageFilename[ExportLibraryHeader->ImageFilenameLength] != 0)
            LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Library filename has invalid length or is not terminated correctly for library index %d of image %s", LibraryIndex, ImportImageFilename);

        // Log the information about this library if necessary
        LogLink(LINKER_LOG_LEVEL_VERBOSE, "- %s [version %d, hashing algo %d with %d buckets and %d exports]", ExportLibraryImageFilename,
            ExportLibraryHeader->Version, ExportLibraryHeader->HashingAlgorithm, ExportLibraryHeader->NumExportBuckets, ExportLibraryHeader->NumExports);

        // If this image contains information necessary to resolve cyclic dependencies, check if it has been linked already
        if (ExportLibraryHeader->Version >= LARGE_LOADER_VERSION_CIRCULAR_DEPS && ExportLibraryHeader->ImportSectionHeaderLength > 0)
        {
            // We do not perform additional validation on import directory here (e.g. version validity) because we assume that export and import directories are generated by the same linker
            struct LargeLoaderImportSectionHeader* ExportLibraryImportHeader = (struct LargeLoaderImportSectionHeader*) ((BYTE*) ExportLibraryHeader + ExportLibraryHeader->ImportSectionHeaderOffset);
            const LPVOID* ExportLibraryImportAddressTable = (LPVOID*) ((BYTE*) ExportLibraryImportHeader + ExportLibraryImportHeader->AddressTableOffset);

            // If image that we depend on has not been linked yet (because of cyclic dependencies), link it now
            // Since our image might call functions in the dependency image, which might call functions in its dependency images, we have to get the entire cyclic dependency
            // chain linked by the time we finish linking the image we are currently linking
            if (ExportLibraryImportHeader->NumImports > 0 && ExportLibraryImportAddressTable[0] == 0)
            {
                LogLink(LINKER_LOG_LEVEL_LOG, "Linking dependency library %s out of order because of cyclic dependencies", ExportLibraryImageFilename);
                __large_loader_link(ExportLibraryImageBase, ExportLibraryImportHeader);
            }
        }
    }

    // Resolve imports now
    for (DWORD ImportIndex = 0; ImportIndex < LargeImportSectionHeader->NumImports; ImportIndex++)
    {
        DWORD ImportStartOffset = LargeImportSectionHeader->SingleImportSize * ImportIndex;
        struct LargeLoaderImport* LoaderImport = (struct LargeLoaderImport*) (ImportTable + ImportStartOffset);

        // Make sure the import is null terminated and has a reasonable length
        LPCSTR ImportName = (LPCSTR) ((BYTE*) LoaderImport + LoaderImport->NameOffset);
        if (LoaderImport->NameLen >= 1024 || LoaderImport->NameLen == 0 || ImportName[LoaderImport->NameLen] != 0)
            LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupt image: Import name has invalid length or is not null terminated correctly for import index %d of image %s. NameLen: %d",
                ImportIndex, ImportImageFilename, LoaderImport->NameLen);

        struct LargeLoaderImportResolutionResult ResolvedExportAddress;
        ResolvedExportAddress.MainAddress = NULL;
        ResolvedExportAddress.AuxiliaryAddress = NULL;

        // Attempt to resolve a fully qualified import
        if (LoaderImport->ExportSectionIndex != 0xFFFF)
        {
            // Sanity check the import. If the export section index is invalid, chances are the image is corrupted. Do not attempt to read the import name since it will most likely not be null terminated
            if (LoaderImport->ExportSectionIndex >= LargeImportSectionHeader->NumExportSections)
            {
                LogLink(LINKER_LOG_LEVEL_FATAL, "Corrupted image: Export section index %d out of bounds (number of export sections: %d) for import ordinal {} of image {}",
                   LoaderImport->ExportSectionIndex, LargeImportSectionHeader->NumExportSections, ImportIndex, ImportImageFilename);
            }
            ResolvedExportAddress = ResolveFullyQualifiedImportChecked(LargeImportSectionHeader, LoaderImport);
        }
        else
        {
            // Resolve a wildcard import otherwise
            ResolvedExportAddress = ResolveWildcardImportChecked(LargeImportSectionHeader, LoaderImport);
        }

        // Write the export address to the address table for this import
        LogLink(LINKER_LOG_LEVEL_VERBOSE, "Linked import %s to export address %p", ImportName, ResolvedExportAddress);
        ImportAddressTable[ImportIndex] = ResolvedExportAddress.MainAddress;
        if (AuxiliaryImportAddressTable)
            AuxiliaryImportAddressTable[ImportIndex] = ResolvedExportAddress.AuxiliaryAddress;
    }

    // Restore the original flags on the import address table page to disallow writing to it
    VirtualProtect(ImportAddressTable, ImportAddressTableSize, OldPageProtectionFlags, &OldPageProtectionFlags);

    LogLink(LINKER_LOG_LEVEL_LOG, "Successfully linked image %s", ImportImageFilename);
}

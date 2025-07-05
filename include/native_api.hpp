#ifndef NATIVE_API_HPP
#define NATIVE_API_HPP

#include "shared.hpp"
#include "hash.hpp"
#include "crt.hpp"
#include <cstdint>
#include <cwchar>

namespace syscall::native
{
    inline PPEB getCurrentPEB()
    {
#if SYSCALL_PLATFORM_WINDOWS_64
        return (PEB*)(__readgsqword(0x60));
#elif SYSCALL_PLATFORM_WINDOWS_32
        return (PEB*)(__readfsdword(0x30));
#endif
    }

    inline hashing::Hash_t calculateHashRuntimeCi(const wchar_t* wzData)
    {
        if (!wzData || *wzData == L'\0')
            return 0;

        hashing::Hash_t hash = hashing::polyKey1;
        wchar_t wcCurrent = 0;

        while ((wcCurrent = *wzData++))
        {
            wchar_t wcLower = crt::string::toLower(wcCurrent);
            hash ^= static_cast<hashing::Hash_t>(wcLower);
            hash += std::rotr(hash, 11) + hashing::polyKey2;
        }
        return hash;
    }

    inline hashing::Hash_t calculateHashSuffix(hashing::Hash_t hash, const char* sSuffix)
    {
        if (!sSuffix || *sSuffix == '\0')
            return hash;

        while (*sSuffix)
        {
            hash ^= static_cast<hashing::Hash_t>(*sSuffix++);
            hash += std::rotr(hash, 11) + hashing::polyKey2;
        }
        return hash;
    }

    inline HMODULE getModuleBase(const wchar_t* wzModuleName)
    {
        if (!wzModuleName || *wzModuleName == L'\0')
            return nullptr;

        auto pPeb = getCurrentPEB();
        if (!pPeb || !pPeb->Ldr)
            return nullptr;

        auto pLdrData = pPeb->Ldr;
        auto pListHead = &pLdrData->InMemoryOrderModuleList;
        auto pCurrentEntry = pListHead->Flink;

        while (pCurrentEntry != pListHead)
        {
            auto pEntry = CONTAINING_RECORD(pCurrentEntry, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (pEntry->BaseDllName.Buffer && crt::string::compareIgnoreCase(pEntry->BaseDllName.Buffer, wzModuleName) == 0)
                return reinterpret_cast<HMODULE>(pEntry->DllBase);

            pCurrentEntry = pCurrentEntry->Flink;
        }
        return nullptr;
    }

    inline HMODULE getModuleBase(hashing::Hash_t uModuleHash)
    {
        auto pPeb = getCurrentPEB();
        if (!pPeb || !pPeb->Ldr)
            return nullptr;

        auto pLdrData = pPeb->Ldr;
        auto pListHead = &pLdrData->InMemoryOrderModuleList;
        auto pCurrentEntry = pListHead->Flink;

        while (pCurrentEntry != pListHead)
        {
            auto pEntry = CONTAINING_RECORD(pCurrentEntry, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (pEntry->BaseDllName.Buffer && calculateHashRuntimeCi(pEntry->BaseDllName.Buffer) == uModuleHash)
                return reinterpret_cast<HMODULE>(pEntry->DllBase);

            pCurrentEntry = pCurrentEntry->Flink;
        }
        return nullptr;
    }

    inline void* getExportAddress(HMODULE hModuleBase, const char* szExportName)
    {
        if (!hModuleBase || !szExportName || *szExportName == '\0')
            return nullptr;

        auto pBase = reinterpret_cast<const uint8_t*>(hModuleBase);
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        auto uExportDirRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!uExportDirRva) return nullptr;

        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + uExportDirRva);
        auto pNamesRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfNames);
        auto pOrdinalsRVA = reinterpret_cast<uint16_t*>(pBase + pExportDir->AddressOfNameOrdinals);
        auto pFunctionsRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfFunctions);

        for (uint32_t i = 0; i < pExportDir->NumberOfNames; ++i)
        {
            const char* szCurrentProcName = reinterpret_cast<const char*>(pBase + pNamesRVA[i]);

            if (crt::string::compare(szCurrentProcName, szExportName) == 0)
            {
                uint16_t usOrdinal = pOrdinalsRVA[i];
                uint32_t uFunctionRva = pFunctionsRVA[usOrdinal];
                auto uExportSectionStart = uExportDirRva;
                auto uExportSectionEnd = uExportSectionStart + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

                if (uFunctionRva >= uExportSectionStart && uFunctionRva < uExportSectionEnd)
                {
                    char szForwarderString[256];
                    crt::string::copy(szForwarderString, sizeof(szForwarderString), reinterpret_cast<const char*>(pBase + uFunctionRva));

                    char* szSeparator = crt::string::findChar(szForwarderString, '.');
                    if (!szSeparator)
                        return nullptr;

                    *szSeparator = '\0';
                    char* szForwarderFuncName = szSeparator + 1;
                    char* szForwarderDllName = szForwarderString;

                    wchar_t wzWideDllName[260];

                    crt::string::mbToWcs(wzWideDllName, crt::getCountOf(wzWideDllName), szForwarderDllName);
                    crt::string::concat(wzWideDllName, crt::getCountOf(wzWideDllName), L".dll");

                    HMODULE hForwarderModuleBase = getModuleBase(wzWideDllName);
                    if (!hForwarderModuleBase)
                        return nullptr;

                    return getExportAddress(hForwarderModuleBase, szForwarderFuncName);
                }
                else
                    return const_cast<uint8_t*>(pBase) + uFunctionRva;
            }
        }
        return nullptr;
    }

    inline void* getExportAddress(HMODULE hModuleBase, hashing::Hash_t uExportHash)
    {
        if (!hModuleBase)
            return nullptr;

        auto pBase = reinterpret_cast<uint8_t*>(hModuleBase);
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        auto uExportDirRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!uExportDirRva)
            return nullptr;

        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + uExportDirRva);
        auto pNamesRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfNames);
        auto pOrdinalsRVA = reinterpret_cast<uint16_t*>(pBase + pExportDir->AddressOfNameOrdinals);
        auto pFunctionsRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfFunctions);

        for (uint32_t i = 0; i < pExportDir->NumberOfNames; ++i)
        {
            const char* szCurrentProcName = reinterpret_cast<const char*>(pBase + pNamesRVA[i]);

            if (hashing::calculateHashRuntime(szCurrentProcName) == uExportHash)
            {
                uint16_t usOrdinal = pOrdinalsRVA[i];
                uint32_t uFunctionRva = pFunctionsRVA[usOrdinal];
                auto uExportSectionStart = uExportDirRva;
                auto uExportSectionEnd = uExportSectionStart + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

                if (uFunctionRva >= uExportSectionStart && uFunctionRva < uExportSectionEnd)
                {
                    char szForwarderString[256];
                    crt::string::copy(szForwarderString, sizeof(szForwarderString), reinterpret_cast<const char*>(pBase + uFunctionRva));

                    char* szSeparator = crt::string::findChar(szForwarderString, '.');
                    if (!szSeparator)
                        return nullptr;

                    *szSeparator = '\0';
                    char* szForwarderFuncName = szSeparator + 1;
                    char* szForwarderDllName = szForwarderString;

                    wchar_t wzWideDllName[260];
                    crt::string::mbToWcs(wzWideDllName, crt::getCountOf(wzWideDllName), szForwarderDllName);

                    hashing::Hash_t uForwarderDllHash = calculateHashRuntimeCi(wzWideDllName);
                    if (!uForwarderDllHash)
                        return nullptr;

                    uForwarderDllHash = calculateHashSuffix(uForwarderDllHash, ".dll");

                    HMODULE hForwarderModuleBase = getModuleBase(uForwarderDllHash);
                    if (!hForwarderModuleBase)
                        return nullptr;

                    hashing::Hash_t uForwarderFuncHash = hashing::calculateHashRuntime(szForwarderFuncName);
                    return getExportAddress(hForwarderModuleBase, uForwarderFuncHash);
                }
                else
                    return const_cast<uint8_t*>(pBase) + uFunctionRva;
            }
        }
        return nullptr;
    }

    SYSCALL_FORCE_INLINE uint64_t rdtscp()
    {
        unsigned int uProcessorId;
#if SYSCALL_COMPILER_MSVC
        return __rdtscp(&uProcessorId);
#elif SYSCALL_COMPILER_GCC || SYSCALL_COMPILER_CLANG
        return __builtin_ia32_rdtscp(&uProcessorId);
#else
#error "Compiler not supported for RDTSCP intrinsic"
#endif
    }
}

#endif
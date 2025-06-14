#ifndef NATIVE_API_HPP
#define NATIVE_API_HPP

#include "shared.hpp"
#include "hash.hpp"
#include "crt.hpp"
#include <cstdint>
#include <cwchar>

namespace native
{
    inline PPEB getCurrentPEB()
    {
#ifdef _M_X64
        return (PEB*)(__readgsqword(0x60));
#elif _WIN32
        return (PEB*)(__readfsdword(0x30));
#endif
    }

    inline hashing::Hash_t calculateHashRuntimeCi(const wchar_t* wzData)
    {
        if (!wzData)
            return 0;

        hashing::Hash_t hash = hashing::polyKey1;
        wchar_t wcCurrent = 0;

        while ((wcCurrent = *wzData++))
        {
            char cAnsiChar = static_cast<char>(crt::string::toLower(wcCurrent));
            hash ^= static_cast<hashing::Hash_t>(cAnsiChar);
            hash += std::rotr(hash, 11) + hashing::polyKey2;
        }
        return hash;
    }

    inline HMODULE getModuleBase(const wchar_t* wzModuleName)
    {
        auto pPeb = getCurrentPEB();
        if (!pPeb || !pPeb->Ldr)
            return nullptr;

        auto pLdrData = pPeb->Ldr;
        auto pListHead = &pLdrData->InMemoryOrderModuleList;
        auto pCurrentEntry = pListHead->Flink;

        while (pCurrentEntry != pListHead)
        {
            auto pEntry = reinterpret_cast<SHARED_LDR_DATA_TABLE_ENTRY*>(CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
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
            auto pEntry = reinterpret_cast<SHARED_LDR_DATA_TABLE_ENTRY*>(CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
            if (pEntry->BaseDllName.Buffer && calculateHashRuntimeCi(pEntry->BaseDllName.Buffer) == uModuleHash)
                return reinterpret_cast<HMODULE>(pEntry->DllBase);

            pCurrentEntry = pCurrentEntry->Flink;
        }
        return nullptr;
    }

    inline void* getExportAddress(HMODULE hModuleBase, const char* szExportName)
    {
        if (!hModuleBase || !szExportName) 
            return nullptr;

        auto pBase = reinterpret_cast<uint8_t*>(hModuleBase);
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
                    return pBase + uFunctionRva;
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
                    crt::string::concat(wzWideDllName, crt::getCountOf(wzWideDllName), L".dll");

                    hashing::Hash_t uForwarderDllHash = calculateHashRuntimeCi(wzWideDllName);
                    HMODULE hForwarderModuleBase = getModuleBase(uForwarderDllHash);
                    if (!hForwarderModuleBase) 
                        return nullptr;

                    hashing::Hash_t uForwarderFuncHash = hashing::calculateHashRuntime(szForwarderFuncName);
                    return getExportAddress(hForwarderModuleBase, uForwarderFuncHash);
                }
                else
                    return pBase + uFunctionRva;
            }
        }
        return nullptr;
    }

    SYSCALL_FORCE_INLINE uint64_t rdtscp()
    {
        unsigned int uProcessorId; 
#if defined(_MSC_VER)
        return __rdtscp(&uProcessorId);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_ia32_rdtscp(&uProcessorId);
#else
#error "Compiler not supported for RDTSCP intrinsic"
#endif
    }
}

#endif
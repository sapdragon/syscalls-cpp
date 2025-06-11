#ifndef NATIVE_API_HPP
#define NATIVE_API_HPP

#include "shared.hpp"
#include <cstdint>
#include <cwchar>  
#include <string.h> 

namespace native
{
    inline HMODULE getModuleBase(const wchar_t* wzModuleName)
    {
        auto pPeb = reinterpret_cast<PPEB>(__readgsqword(0x60));
        if (!pPeb || !pPeb->Ldr)
            return nullptr;

        auto pLdrData = pPeb->Ldr;
        auto pListHead = &pLdrData->InMemoryOrderModuleList;
        auto pCurrentEntry = pListHead->Flink;

        while (pCurrentEntry != pListHead)
        {
            auto pEntry = reinterpret_cast <SHARED_LDR_DATA_TABLE_ENTRY*>(CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
            if (pEntry->BaseDllName.Buffer && STR_ICMP(pEntry->BaseDllName.Buffer, wzModuleName) == 0)
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
        if (!uExportDirRva)
            return nullptr;

        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + uExportDirRva);

        auto pNamesRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfNames);
        auto pOrdinalsRVA = reinterpret_cast<uint16_t*>(pBase + pExportDir->AddressOfNameOrdinals);
        auto pFunctionsRVA = reinterpret_cast<uint32_t*>(pBase + pExportDir->AddressOfFunctions);

        for (uint32_t i = 0; i < pExportDir->NumberOfNames; ++i)
        {
            const char* szCurrentProcName = reinterpret_cast<const char*>(pBase + pNamesRVA[i]);

            if (strcmp(szCurrentProcName, szExportName) == 0)
            {
                uint16_t usOrdinal = pOrdinalsRVA[i];
                uint32_t uFunctionRva = pFunctionsRVA[usOrdinal];

                auto uExportSectionStart = uExportDirRva;
                auto uExportSectionEnd = uExportSectionStart + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

                if (uFunctionRva >= uExportSectionStart && uFunctionRva < uExportSectionEnd)
                {
                    char szForwarderString[256];
                    strcpy_s(szForwarderString, sizeof(szForwarderString), reinterpret_cast<const char*>(pBase + uFunctionRva));

                    char* szSeparator = strchr(szForwarderString, '.');
                    if (!szSeparator) 
                        return nullptr;

                    *szSeparator = '\0';
                    char* szForwarderFuncName = szSeparator + 1;
                    char* szForwarderDllName = szForwarderString;

                    wchar_t wzWideDllName[260];
                    size_t uCConvertedChars = 0;
                    mbstowcs_s(&uCConvertedChars, wzWideDllName, _countof(wzWideDllName), szForwarderDllName, _TRUNCATE);
                    wcscat_s(wzWideDllName, _countof(wzWideDllName), L".dll");

                    HMODULE hForwarderModuleBase = getModuleBase(wzWideDllName);
                    if (!hForwarderModuleBase)
                    {
                        // @todo / sapdragon: maybe add load library?
                        return nullptr;
                    }

                    return getExportAddress(hForwarderModuleBase, szForwarderFuncName);
                }
                else
                    return pBase + uFunctionRva;
            }
        }

        return nullptr;
    }
}
#endif // NATIVE_API_HPP
#ifndef NATIVE_API_HPP
#define NATIVE_API_HPP

#include "shared.hpp"
#include "crt.hpp"
#include "hash.hpp"
#include <cstdint>
#include <cwchar>

namespace syscall::native
{
    namespace detail
    {
        inline hashing::Hash_t appendDllExtensionToHash(hashing::Hash_t uHash)
        {
            for (char c : {'.', 'd', 'l', 'l'})
            {
                uHash ^= static_cast<hashing::Hash_t>(c);
                uHash += std::rotr(uHash, 11) + hashing::polyKey2;
            }
            return uHash;
        }

        struct ForwarderInfo_t
        {
            char m_szDllName[256];
            char* m_szFuncName;
            bool m_bValid;
        };

        inline ForwarderInfo_t parseForwarderString(const uint8_t* pBase, uint32_t uFunctionRva)
        {
            ForwarderInfo_t forwarderInfo{};
            std::copy_n(reinterpret_cast<const char*>(pBase + uFunctionRva),
                        sizeof(forwarderInfo.m_szDllName) - 1, forwarderInfo.m_szDllName);
            forwarderInfo.m_szDllName[sizeof(forwarderInfo.m_szDllName) - 1] = '\0';

            auto pSeparator = std::ranges::find(forwarderInfo.m_szDllName, '.');
            if (pSeparator == std::end(forwarderInfo.m_szDllName) || *pSeparator == '\0')
            {
                forwarderInfo.m_bValid = false;
                return forwarderInfo;
            }

            *pSeparator = '\0';
            forwarderInfo.m_szFuncName = pSeparator + 1;
            forwarderInfo.m_bValid = true;
            return forwarderInfo;
        }
    }

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

    inline hashing::Hash_t calculateHashRuntimeCi(const char* szData)
    {
        if (!szData)
            return 0;

        hashing::Hash_t hash = hashing::polyKey1;
        char cCurrent = 0;

        while ((cCurrent = *szData++))
        {
            char cLower = crt::string::toLower(cCurrent);
            hash ^= static_cast<hashing::Hash_t>(cLower);
            hash += std::rotr(hash, 11) + hashing::polyKey2;
        }
        return hash;
    }

    inline HMODULE getModuleBase(const wchar_t* wzModuleName)
    {
        if (!wzModuleName)
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
            auto szCurrentProcName = reinterpret_cast<const char*>(pBase + pNamesRVA[i]);

            if (std::string_view{szCurrentProcName} != std::string_view{szExportName})
                continue;

            const uint16_t usOrdinal = pOrdinalsRVA[i];
            const uint32_t uFunctionRva = pFunctionsRVA[usOrdinal];
            auto uExportSectionStart = uExportDirRva;
            auto uExportSectionEnd = uExportSectionStart + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if (uFunctionRva < uExportSectionStart || uFunctionRva >= uExportSectionEnd)
                return pBase + uFunctionRva;

            auto forwarder = detail::parseForwarderString(pBase, uFunctionRva);
            if (!forwarder.m_bValid)
                return nullptr;

            hashing::Hash_t uForwarderDllHash = calculateHashRuntimeCi(forwarder.m_szDllName);
            if (!uForwarderDllHash)
                return nullptr;

            uForwarderDllHash = detail::appendDllExtensionToHash(uForwarderDllHash);

            const HMODULE hForwarderModuleBase = getModuleBase(uForwarderDllHash);
            if (!hForwarderModuleBase)
                return nullptr;

            return getExportAddress(hForwarderModuleBase, forwarder.m_szFuncName);
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

            if (hashing::calculateHashRuntime(szCurrentProcName) != uExportHash)
                continue;

            uint16_t usOrdinal = pOrdinalsRVA[i];
            uint32_t uFunctionRva = pFunctionsRVA[usOrdinal];
            auto uExportSectionStart = uExportDirRva;
            auto uExportSectionEnd = uExportSectionStart + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if (uFunctionRva < uExportSectionStart || uFunctionRva >= uExportSectionEnd)
                return pBase + uFunctionRva;

            auto forwarder = detail::parseForwarderString(pBase, uFunctionRva);
            if (!forwarder.m_bValid)
                return nullptr;

            hashing::Hash_t uForwarderDllHash = calculateHashRuntimeCi(forwarder.m_szDllName);
            if (!uForwarderDllHash)
                return nullptr;

            uForwarderDllHash = detail::appendDllExtensionToHash(uForwarderDllHash);

            HMODULE hForwarderModuleBase = getModuleBase(uForwarderDllHash);
            if (!hForwarderModuleBase)
                return nullptr;

            hashing::Hash_t uForwarderFuncHash = hashing::calculateHashRuntime(forwarder.m_szFuncName);
            return getExportAddress(hForwarderModuleBase, uForwarderFuncHash);
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
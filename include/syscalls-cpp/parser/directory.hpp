#ifndef SYSCALL_PARSER_DIRECTORY_HPP
#define SYSCALL_PARSER_DIRECTORY_HPP

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../hash.hpp"
#include "../platform.hpp"
#include "../types.hpp"

namespace syscall::policies::parser
{
    struct directory
    {
        static std::vector<SyscallEntry_t> parse(const ModuleInfo_t& module)
        {
            std::vector<SyscallEntry_t> vecFoundSyscalls;
            // @note / sapdragon: exception parser on x64
            if constexpr (platform::isWindows64)
            {
                auto uExceptionDirRva = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
                if (!uExceptionDirRva)
                    return vecFoundSyscalls;

                auto pRuntimeFunctions = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(module.m_pModuleBase + uExceptionDirRva);
                auto uExceptionDirSize = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
                auto uFunctionCount = uExceptionDirSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

                auto pFunctionsRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfFunctions);
                auto pNamesRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNames);
                auto pOrdinalsRva = reinterpret_cast<uint16_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNameOrdinals);

                std::unordered_map<uint32_t, const char*> mapRvaToName;
                for (uint32_t i = 0; i < module.m_pExportDir->NumberOfNames; ++i)
                {
                    const char* szName = reinterpret_cast<const char*>(module.m_pModuleBase + pNamesRVA[i]);
                    uint16_t uOrdinal = pOrdinalsRva[i];
                    uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];
                    mapRvaToName[uFunctionRva] = szName;
                }

                uint32_t uSyscallNumber = 0;
                for (DWORD i = 0; i < uFunctionCount; ++i)
                {
                    auto pFunction = &pRuntimeFunctions[i];
                    if (pFunction->BeginAddress == 0)
                        break;

                    auto it = mapRvaToName.find(pFunction->BeginAddress);
                    if (it != mapRvaToName.end())
                    {
                        const char* szName = it->second;

                        if (hashing::calculateHashRuntime(szName, 2) == hashing::calculateHash("Zw"))
                        {
                            char szNtName[128]{};
                            std::copy_n(szName, std::min(std::strlen(szName), sizeof(szNtName) - 1), szNtName);
                            szNtName[0] = 'N';
                            szNtName[1] = 't';

                            const SyscallKey_t key = SYSCALL_ID_RT(szNtName);

                            vecFoundSyscalls.push_back(SyscallEntry_t{ key, uSyscallNumber, 0 });
                            uSyscallNumber++;
                        }
                    }
                }
            }
            // @note / sapdragon: sorting zw exports
            else
            {
                auto pFunctionsRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfFunctions);
                auto pNamesRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNames);
                auto pOrdinalsRva = reinterpret_cast<uint16_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNameOrdinals);

                std::vector<std::pair<uintptr_t, const char*>> vecZwFunctions;
                for (uint32_t i = 0; i < module.m_pExportDir->NumberOfNames; ++i)
                {
                    const char* szName = reinterpret_cast<const char*>(module.m_pModuleBase + pNamesRVA[i]);

                    if (szName[0] == 'Z' && szName[1] == 'w')
                    {
                        uint16_t uOrdinal = pOrdinalsRva[i];
                        uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];

                        auto pExportSectionStart = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                        auto pExportSectionEnd = pExportSectionStart + module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                        if (uFunctionRva >= pExportSectionStart && uFunctionRva < pExportSectionEnd)
                            continue;

                        uintptr_t uFunctionAddress = reinterpret_cast<uintptr_t>(module.m_pModuleBase + uFunctionRva);
                        vecZwFunctions.push_back({ uFunctionAddress, szName });
                    }
                }

                if (vecZwFunctions.empty())
                    return vecFoundSyscalls;

                std::sort(vecZwFunctions.begin(), vecZwFunctions.end(),
                    [](const auto& a, const auto& b) {
                        return a.first < b.first;
                    });

                uint32_t uSyscallNumber = 0;
                for (const auto& [_, szName] : vecZwFunctions)
                {
                    char szNtName[128]{};
                    std::copy_n(szName, std::min(std::strlen(szName), sizeof(szNtName) - 1), szNtName);
                    szNtName[0] = 'N';
                    szNtName[1] = 't';

                    const SyscallKey_t key = SYSCALL_ID_RT(szNtName);
                    vecFoundSyscalls.push_back(SyscallEntry_t{ key, uSyscallNumber, 0 });
                    uSyscallNumber++;
                }
            }

            return vecFoundSyscalls;
        }
    };
}

#endif

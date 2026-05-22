#ifndef SYSCALL_PARSER_SIGNATURE_HPP
#define SYSCALL_PARSER_SIGNATURE_HPP

#include <cstdint>
#include <vector>

#include "../hash.hpp"
#include "../platform.hpp"
#include "../types.hpp"

namespace syscall::policies::parser
{
    struct signature
    {
        static std::vector<SyscallEntry_t> parse(const ModuleInfo_t& module)
        {
            std::vector<SyscallEntry_t> vecFoundSyscalls;

            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < module.m_pExportDir->NumberOfNames; i++)
            {
                const char* szName = reinterpret_cast<const char*>(module.m_pModuleBase + pNamesRVA[i]);

                if (hashing::calculateHashRuntime(szName, 2) != hashing::calculateHash("Nt"))
                    continue;

                uint16_t uOrdinal = pOrdinalsRva[i];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];

                auto pExportSectionStart = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                auto pExportSectionEnd = pExportSectionStart + module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                if (uFunctionRva >= pExportSectionStart && uFunctionRva < pExportSectionEnd)
                    continue;

                uint8_t* pFunctionStart = module.m_pModuleBase + uFunctionRva;
                uint32_t uSyscallNumber = 0;
                bool bSyscallFound = false;

                if constexpr (platform::isWindows64)
                {
                    if (*reinterpret_cast<uint32_t*>(pFunctionStart) == 0xB8D18B4C)
                    {
                        uSyscallNumber = *reinterpret_cast<uint32_t*>(pFunctionStart + 4);
                        bSyscallFound = true;
                    }
                }

                if constexpr (platform::isWindows32)
                {
                    if (*pFunctionStart == 0xB8)
                    {
                        uSyscallNumber = *reinterpret_cast<uint32_t*>(pFunctionStart + 1);
                        bSyscallFound = true;
                    }
                }
                // @note / SapDragon: checks hooks on x64
                if constexpr (platform::isWindows64)
                {
                    if (isFunctionHooked(pFunctionStart) && !bSyscallFound)
                    {
                        // @note / SapDragon: stable only on x64

                        // @note / SapDragon: search up
                        for (int j = 1; j < 20; ++j)
                        {
                            uint8_t* pNeighborFunc = pFunctionStart - (j * 0x20);
                            if (reinterpret_cast<uintptr_t>(pNeighborFunc) < reinterpret_cast<uintptr_t>(module.m_pModuleBase)) break;
                            if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                            {
                                uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                                uSyscallNumber = uNeighborSyscall + j;
                                bSyscallFound = true;
                                break;
                            }
                        }

                        // @note / SapDragon: search down
                        if (!bSyscallFound)
                        {
                            for (int j = 1; j < 20; ++j)
                            {
                                uint8_t* pNeighborFunc = pFunctionStart + (j * 0x20);
                                if (reinterpret_cast<uintptr_t>(pNeighborFunc) > (reinterpret_cast<uintptr_t>(module.m_pModuleBase) + module.m_pNtHeaders->OptionalHeader.SizeOfImage)) break;
                                if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                                {
                                    uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                                    uSyscallNumber = uNeighborSyscall - j;
                                    bSyscallFound = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (bSyscallFound)
                {
                    const SyscallKey_t key = SYSCALL_ID_RT(szName);
                    vecFoundSyscalls.push_back(SyscallEntry_t{
                                key,
                                uSyscallNumber,
                                0
                        });
                }
            }
            return vecFoundSyscalls;
        }

    private:
        static bool isFunctionHooked(const uint8_t* pFunctionStart)
        {
            const uint8_t* pCurrent = pFunctionStart;

            while (*pCurrent == 0x90)
                pCurrent++;

            switch (pCurrent[0])
            {
                // @note / SapDragon: JMP rel32
            case 0xE9:
                // @note / SapDragon: JMP rel8
            case 0xEB:
                // @note / SapDragon: push imm32
            case 0x68:
                return true;

                // @note / SapDragon: jmp [mem] / jmp [rip + offset]
            case 0xFF:
                if (pCurrent[1] == 0x25)
                    return true;
                break;

                // @note / SapDragon: int3...
            case 0xCC:
                return true;

                // @note / SapDragon: ud2
            case 0x0F:
                if (pCurrent[1] == 0x0B)
                    return true;
                break;

                // @note / SapDragon: int 0x3
            case 0xCD:
                if (pCurrent[1] == 0x03)
                    return true;
                break;

            default:
                break;
            }

            return false;
        }
    };
}

#endif

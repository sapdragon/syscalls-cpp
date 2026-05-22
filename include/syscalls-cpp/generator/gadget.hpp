#ifndef SYSCALL_GENERATOR_GADGET_HPP
#define SYSCALL_GENERATOR_GADGET_HPP

#include <cstddef>
#include <cstdint>

#include "../platform.hpp"

namespace syscall::policies::generator
{
#if SYSCALL_PLATFORM_WINDOWS_64
    // @note / SapDragon: supports only on x64 now
    struct gadget
    {
        static constexpr bool bRequiresGadget = true;
        static constexpr size_t getStubSize() { return 32; }
        static void generate(uint8_t* pBuffer, uint32_t uSyscallNumber, void* pGadgetAddress)
        {
            // @note / SapDragon: mov r10, rcx
            pBuffer[0] = 0x49;
            pBuffer[1] = 0x89;
            pBuffer[2] = 0xCA;

            // @note / SapDragon: mov eax, syscallNumber
            pBuffer[3] = 0xB8;
            *reinterpret_cast<uint32_t*>(&pBuffer[4]) = uSyscallNumber;

            // @note / SapDragon: mov r11, gadgetAddress
            pBuffer[8] = 0x49;
            pBuffer[9] = 0xBB;
            *reinterpret_cast<uint64_t*>(&pBuffer[10]) = reinterpret_cast<uint64_t>(pGadgetAddress);

            // @note / SapDragon: push r11
            pBuffer[18] = 0x41;
            pBuffer[19] = 0x53;

            // @note / SapDragon: ret
            pBuffer[20] = 0xC3;
        }
    };
#endif
}

#endif

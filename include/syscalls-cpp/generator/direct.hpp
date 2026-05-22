#ifndef SYSCALL_GENERATOR_DIRECT_HPP
#define SYSCALL_GENERATOR_DIRECT_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "../platform.hpp"

namespace syscall::policies::generator
{
    struct direct
    {
        static constexpr bool bRequiresGadget = false;

#if SYSCALL_PLATFORM_WINDOWS_64
        inline static constinit std::array<uint8_t, 18> arrShellcode =
        {
            0x51,                               // push rcx
            0x41, 0x5A,                         // pop r10
            0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0x00000000 (syscall number placeholder)
            0x0F, 0x05,                         // syscall
            0x48, 0x83, 0xC4, 0x08,             // add rsp, 8
            0xFF, 0x64, 0x24, 0xF8              // jmp qword ptr [rsp-8]
        };
#elif SYSCALL_PLATFORM_WINDOWS_32
        inline static constinit std::array<uint8_t, 15> arrShellcode =
        {
            0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0x00000000 (syscall number placeholder)
            0x89, 0xE2,                         // mov edx, esp
            0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, // call dword ptr fs:[0xC0]
            0xC3                                // ret
        };
#endif
        static void generate(uint8_t* pBuffer, uint32_t uSyscallNumber, void* /*pGadgetAddress*/)
        {
            std::copy_n(arrShellcode.data(), arrShellcode.size(), pBuffer);
            if constexpr (platform::isWindows64)
                *reinterpret_cast<uint32_t*>(pBuffer + 4) = uSyscallNumber;
            else
                *reinterpret_cast<uint32_t*>(pBuffer + 1) = uSyscallNumber;
        }

        static constexpr size_t getStubSize() { return arrShellcode.size(); }
    };
}

#endif

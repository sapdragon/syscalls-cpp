#ifndef SYSCALL_GENERATOR_EXCEPTION_HPP
#define SYSCALL_GENERATOR_EXCEPTION_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace syscall::policies::generator
{
    struct exception
    {
        static constexpr bool bRequiresGadget = true;
        static constexpr bool bRequiresExceptionDispatch = true;
        static constexpr size_t getStubSize() { return 8; }
        static void generate(uint8_t* pBuffer, uint32_t /*uSyscallNumber*/, void* /*pGadgetAddress*/)
        {
            pBuffer[0] = 0x0F;
            pBuffer[1] = 0x0B;
            pBuffer[2] = 0xC3;
            std::fill_n(pBuffer + 3, getStubSize() - 3, 0x90);
        }
    };
}

#endif

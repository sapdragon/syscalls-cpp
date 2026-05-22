#ifndef SYSCALL_TYPES_HPP
#define SYSCALL_TYPES_HPP

#include <cstdint>
#include <string>

#include "shared.hpp"
#include "hash.hpp"

namespace syscall
{
    struct ModuleInfo_t
    {
        uint8_t* m_pModuleBase = nullptr;
        IMAGE_NT_HEADERS* m_pNtHeaders = nullptr;
        IMAGE_EXPORT_DIRECTORY* m_pExportDir = nullptr;
    };

#ifdef SYSCALLS_NO_HASH
    using SyscallKey_t = std::string;
#else
    using SyscallKey_t = hashing::Hash_t;
#endif

    struct SyscallEntry_t
    {
        SyscallKey_t m_key;
        uint32_t m_uSyscallNumber;
        uint32_t m_uOffset;
    };
}

#endif

#ifndef SYSCALL_ALLOCATOR_MEMORY_HPP
#define SYSCALL_ALLOCATOR_MEMORY_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../hash.hpp"
#include "../native_api.hpp"
#include "../shared.hpp"

namespace syscall::policies::allocator
{
    struct memory
    {
        static bool allocate(size_t uRegionSize, const std::span<const uint8_t> vecBuffer, void*& pOutRegion, HANDLE& /*unused*/)
        {
            HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));

            auto fNtAllocate = reinterpret_cast<native::NtAllocateVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtAllocateVirtualMemory")));
            auto fNtProtect = reinterpret_cast<native::NtProtectVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtProtectVirtualMemory")));
            if (!fNtAllocate || !fNtProtect)
                return false;

            pOutRegion = nullptr;
            SIZE_T uSize = uRegionSize;
            NTSTATUS status = fNtAllocate(native::getCurrentProcess(), &pOutRegion, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (!NT_SUCCESS(status) || !pOutRegion)
                return false;

            std::copy_n(vecBuffer.data(), uRegionSize, static_cast<uint8_t*>(pOutRegion));
            ULONG oldProtection = 0;
            uSize = uRegionSize;
            status = fNtProtect(native::getCurrentProcess(), &pOutRegion, &uSize, PAGE_EXECUTE_READ, &oldProtection);

            if (!NT_SUCCESS(status))
            {
                uSize = 0;
                fNtAllocate(native::getCurrentProcess(), &pOutRegion, 0, &uSize, MEM_RELEASE, 0);
                pOutRegion = nullptr;
                return false;
            }

            return true;
        }

        static void release(void* pRegion, HANDLE /*heapHandle*/)
        {
            HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));

            if (pRegion)
            {
                auto fNtFree = reinterpret_cast<native::NtFreeVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtFreeVirtualMemory")));
                if (fNtFree)
                {
                    SIZE_T uSize = 0;
                    fNtFree(native::getCurrentProcess(), &pRegion, &uSize, MEM_RELEASE);
                }
            }
        }
    };
}

#endif

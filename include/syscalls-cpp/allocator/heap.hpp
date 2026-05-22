#ifndef SYSCALL_ALLOCATOR_HEAP_HPP
#define SYSCALL_ALLOCATOR_HEAP_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../hash.hpp"
#include "../native_api.hpp"
#include "../shared.hpp"

namespace syscall::policies::allocator
{
    struct heap
    {
        static bool allocate(size_t uRegionSize, const std::span<const uint8_t> vecBuffer, void*& pOutRegion, HANDLE& hOutHeapHandle)
        {
            HMODULE hNtdll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
            if (!hNtdll)
                return false;

            auto fRtlCreateHeap = reinterpret_cast<native::RtlCreateHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlCreateHeap")));
            auto fRtlAllocateHeap = reinterpret_cast<native::RtlAllocateHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlAllocateHeap")));
            if (!fRtlCreateHeap || !fRtlAllocateHeap)
                return false;

            hOutHeapHandle = fRtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE, nullptr, 0, 0, nullptr, nullptr);
            if (!hOutHeapHandle)
                return false;

            pOutRegion = fRtlAllocateHeap(hOutHeapHandle, 0, uRegionSize);
            if (!pOutRegion)
            {
                release(nullptr, hOutHeapHandle);
                hOutHeapHandle = nullptr;
                return false;
            }

            std::copy_n(vecBuffer.data(), uRegionSize, static_cast<uint8_t*>(pOutRegion));
            return true;
        }

        static void release(void* /*region*/, HANDLE hHeapHandle)
        {
            if (hHeapHandle)
            {
                HMODULE hNtdll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
                if (!hNtdll)
                    return;

                auto fRtlDestroyHeap = reinterpret_cast<native::RtlDestroyHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlDestroyHeap")));
                if (fRtlDestroyHeap)
                    fRtlDestroyHeap(hHeapHandle);
            }
        }
    };
}

#endif

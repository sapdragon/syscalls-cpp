#ifndef SYSCALL_ALLOCATOR_SECTION_HPP
#define SYSCALL_ALLOCATOR_SECTION_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../hash.hpp"
#include "../native_api.hpp"
#include "../shared.hpp"

namespace syscall::policies::allocator
{
    struct section
    {
        static bool allocate(size_t uRegionSize, const std::span<const uint8_t> vecBuffer, void*& pOutRegion, HANDLE& /*unused*/)
        {
            HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));

            auto fNtCreateSection = reinterpret_cast<native::NtCreateSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtCreateSection")));
            auto fNtMapView = reinterpret_cast<native::NtMapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtMapViewOfSection")));
            auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
            auto fNtClose = reinterpret_cast<native::NtClose_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtClose")));
            if (!fNtCreateSection || !fNtMapView || !fNtUnmapView || !fNtClose)
                return false;

            HANDLE hSectionHandle = nullptr;
            LARGE_INTEGER sectionSize;
            sectionSize.QuadPart = uRegionSize;

            using enum native::ESectionInherit;
            using enum native::ESectionAllocAttributes;

            NTSTATUS status = fNtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, nullptr, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | static_cast<ULONG>(SECTION_NO_CHANGE), nullptr);
            if (!NT_SUCCESS(status))
                return false;

            void* pTempView = nullptr;
            SIZE_T uViewSize = uRegionSize;
            status = fNtMapView(hSectionHandle, native::getCurrentProcess(), &pTempView, 0, 0, nullptr, &uViewSize, VIEW_SHARE, 0, PAGE_READWRITE);
            if (!NT_SUCCESS(status))
            {
                fNtClose(hSectionHandle);
                return false;
            }

            std::copy_n(vecBuffer.data(), uRegionSize, static_cast<uint8_t*>(pTempView));
            fNtUnmapView(native::getCurrentProcess(), pTempView);
            uViewSize = uRegionSize;
            status = fNtMapView(hSectionHandle, native::getCurrentProcess(), &pOutRegion, 0, 0, nullptr, &uViewSize, native::ESectionInherit::VIEW_SHARE, 0, PAGE_EXECUTE_READ);
            fNtClose(hSectionHandle);
            return NT_SUCCESS(status) && pOutRegion;
        }

        static void release(void* pRegion, HANDLE /*hHeapHandle*/)
        {
            HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
            if (pRegion)
            {
                auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                if (fNtUnmapView)
                    fNtUnmapView(native::getCurrentProcess(), pRegion);
            }
        }
    };
}

#endif

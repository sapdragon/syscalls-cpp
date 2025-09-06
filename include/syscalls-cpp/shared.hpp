#ifndef _SYSCALL_SHARED_HPP_
#define _SYSCALL_SHARED_HPP_

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>

#include "platform.hpp"

namespace syscall::native
{

    [[nodiscard]] inline constexpr bool isSuccess(NTSTATUS status) noexcept 
    {
        return status >= 0;
    }
    constexpr NTSTATUS STATUS_SUCCESS = 0x00000000L;
    constexpr NTSTATUS STATUS_UNSUCCESSFUL = 0xC0000001L;
    constexpr NTSTATUS STATUS_PROCEDURE_NOT_FOUND = 0xC000007A;

    inline constexpr HANDLE getCurrentProcess() noexcept 
    {
        return reinterpret_cast<HANDLE>(-1);
    }

    enum class ESectionInherit : DWORD 
    {
        VIEW_SHARE = 1,
        VIEW_UNMAP = 2
    };

    enum class ESectionAllocAttributes : ULONG 
    {
        SECTION_COMMIT = SEC_COMMIT,
        SECTION_IMAGE = SEC_IMAGE,
        SECTION_IMAGE_NO_EXECUTE = SEC_IMAGE_NO_EXECUTE,
        SECTION_LARGE_PAGES = SEC_LARGE_PAGES,
        SECTION_NO_CHANGE = 0x00400000, 
        SECTION_RESERVE = SEC_RESERVE,
    };

    struct LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union {
            LIST_ENTRY HashLinks;
            struct {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
        _ACTIVATION_CONTEXT* EntryPointActivationContext;
        PVOID PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
        PVOID ContextInformation;
        ULONG_PTR OriginalBase;
        LARGE_INTEGER LoadTime;
    };

    using NtCreateSection_t = NTSTATUS(NTAPI*)(
        PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle
        );

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
        HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
        ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize, ESectionInherit InheritDisposition, ULONG AllocationType, ULONG Win32Protect
        );

    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);

    using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
        );

    using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect
        );

    using NtFreeVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType
        );

    using NtClose_t = NTSTATUS(NTAPI*)(HANDLE Handle);
    using RtlCreateHeap_t = PVOID(NTAPI*)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PVOID Parameters);
    using RtlAllocateHeap_t = PVOID(NTAPI*)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    using RtlDestroyHeap_t = PVOID(NTAPI*)(PVOID HeapHandle);

} // syscall::native

#endif
#ifndef _SHARED_HPP_
#define _SHARED_HPP_

#include <Windows.h>
#include <winternl.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS 0x00000000

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)-1)
#endif

#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00400000
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND 0xC000007A
#endif

#ifndef ViewShare
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#endif

using NtCreateSection_t = NTSTATUS(NTAPI*)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

#endif
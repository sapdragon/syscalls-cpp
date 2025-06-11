#ifndef _SHARED_HPP_
#define _SHARED_HPP_


#if defined(_MSC_VER)
#define SYSCALL_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define SYSCALL_FORCE_INLINE inline __attribute__((always_inline))
#else
#define SYSCALL_FORCE_INLINE inline
#endif



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

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
    );

struct SHARED_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    USHORT TlsIndex;                                                        //0x6e
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x70
        struct
        {
            VOID* SectionPointer;                                           //0x70
            ULONG CheckSum;                                                 //0x78
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x80
        VOID* LoadedImports;                                                //0x80
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* PatchInformation;                                                 //0x90
    struct _LIST_ENTRY ForwarderLinks;                                      //0x98
    struct _LIST_ENTRY ServiceTagLinks;                                     //0xa8
    struct _LIST_ENTRY StaticLinks;                                         //0xb8
    VOID* ContextInformation;                                               //0xc8
    ULONGLONG OriginalBase;                                                 //0xd0
    union _LARGE_INTEGER LoadTime;                                          //0xd8
};

#if defined(_MSC_VER)
#define STR_ICMP _wcsicmp
#else
#define STR_ICMP wcscasecmp
#endif

#endif
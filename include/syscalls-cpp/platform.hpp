#ifndef _SYSCALL_PLATFORM_HPP_
#define _SYSCALL_PLATFORM_HPP_

#if defined(_WIN64)
#define SYSCALL_PLATFORM_WINDOWS 1
#define SYSCALL_PLATFORM_WINDOWS_64 1
#define SYSCALL_PLATFORM_WINDOWS_32 0
#elif defined(_WIN32)
#define SYSCALL_PLATFORM_WINDOWS 1
#define SYSCALL_PLATFORM_WINDOWS_64 0
#define SYSCALL_PLATFORM_WINDOWS_32 1
#else
#define SYSCALL_PLATFORM_WINDOWS 0
#endif

#if defined(__linux__)
#define SYSCALL_PLATFORM_LINUX 1
#else
#define SYSCALL_PLATFORM_LINUX 0
#endif

#if defined(_MSC_VER)
#define SYSCALL_COMPILER_MSVC 1
#else
#define SYSCALL_COMPILER_MSVC 0
#endif

#if defined(__clang__)
#define SYSCALL_COMPILER_CLANG 1
#else
#define SYSCALL_COMPILER_CLANG 0
#endif

#if defined(__GNUC__) && !SYSCALL_COMPILER_CLANG
#define SYSCALL_COMPILER_GCC 1
#else
#define SYSCALL_COMPILER_GCC 0
#endif

#if SYSCALL_PLATFORM_WINDOWS_64
#define SYSCALL_API __stdcall
#else
#define SYSCALL_API __cdecl
#endif

#if SYSCALL_COMPILER_MSVC
#define SYSCALL_FORCE_INLINE __forceinline
#elif SYSCALL_COMPILER_GCC || SYSCALL_COMPILER_CLANG
#define SYSCALL_FORCE_INLINE inline __attribute__((always_inline))
#else
#define SYSCALL_FORCE_INLINE inline
#endif

namespace syscall::platform
{
    constexpr bool isWindows = (SYSCALL_PLATFORM_WINDOWS == 1);
    constexpr bool isWindows64 = (SYSCALL_PLATFORM_WINDOWS_64 == 1);
    constexpr bool isWindows32 = (SYSCALL_PLATFORM_WINDOWS_32 == 1);
    constexpr bool isLinux = (SYSCALL_PLATFORM_LINUX == 1);

    constexpr bool isMSVC = (SYSCALL_COMPILER_MSVC == 1);
    constexpr bool IsClang = (SYSCALL_COMPILER_CLANG == 1);
    constexpr bool IsGCC = (SYSCALL_COMPILER_GCC == 1);

    static_assert(isWindows, "Unsupported OS");
    static_assert(isMSVC || IsClang || IsGCC, "Unsupported compiler");
}

#endif
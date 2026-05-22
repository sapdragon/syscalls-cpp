#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <fstream>
#include <functional>
#include <mutex>
#include <cstring>
#include <utility>
#include <concepts> 
#include <array>
#include <random>
#include <algorithm>
#include <ranges>
#include <span>
#include <type_traits>

#include "shared.hpp"
#include "hash.hpp"
#include "native_api.hpp"
#include "types.hpp"


namespace syscall
{

    inline thread_local struct ExceptionContext_t
    {
        bool m_bShouldHandle = false;
        const void* m_pExpectedExceptionAddress = nullptr;
        void* m_pSyscallGadget = nullptr;
        uint32_t m_uSyscallNumber = 0;
    } pExceptionContext;

    class CExceptionContextGuard
    {
    public:
        CExceptionContextGuard(const void* pExpectedAddress, void* pSyscallGadget, uint32_t uSyscallNumber)
        {
            pExceptionContext.m_bShouldHandle = true;
            pExceptionContext.m_pExpectedExceptionAddress = pExpectedAddress;
            pExceptionContext.m_pSyscallGadget = pSyscallGadget;
            pExceptionContext.m_uSyscallNumber = uSyscallNumber;
        }

        ~CExceptionContextGuard()
        {
            pExceptionContext.m_bShouldHandle = false;
        }

        CExceptionContextGuard(const CExceptionContextGuard&) = delete;
        CExceptionContextGuard& operator=(const CExceptionContextGuard&) = delete;
    };

    static LONG NTAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
    {
        if (!pExceptionContext.m_bShouldHandle)
            return EXCEPTION_CONTINUE_SEARCH;

        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
            pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionContext.m_pExpectedExceptionAddress)
        {
            pExceptionContext.m_bShouldHandle = false;
#if SYSCALL_PLATFORM_WINDOWS_64
            pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx;
            pExceptionInfo->ContextRecord->Rax = pExceptionContext.m_uSyscallNumber;
            pExceptionInfo->ContextRecord->Rip = reinterpret_cast<uintptr_t>(pExceptionContext.m_pSyscallGadget);
#else
            uintptr_t uReturnAddressAfterSyscall = reinterpret_cast<uintptr_t>(pExceptionInfo->ExceptionRecord->ExceptionAddress) + 2;

            pExceptionInfo->ContextRecord->Edx = pExceptionInfo->ContextRecord->Esp;

            pExceptionInfo->ContextRecord->Esp -= sizeof(uintptr_t);

            *reinterpret_cast<uintptr_t*>(pExceptionInfo->ContextRecord->Esp) = uReturnAddressAfterSyscall;

            pExceptionInfo->ContextRecord->Eip = reinterpret_cast<uintptr_t>(pExceptionContext.m_pSyscallGadget);
            pExceptionInfo->ContextRecord->Eax = pExceptionContext.m_uSyscallNumber;

#endif


            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
}

#include "allocator/section.hpp"
#include "allocator/heap.hpp"
#include "allocator/memory.hpp"
#include "generator/gadget.hpp"
#include "generator/exception.hpp"
#include "generator/direct.hpp"
#include "parser/directory.hpp"
#include "parser/signature.hpp"

namespace syscall
{

    template<typename T>
    concept IsIAllocationPolicy = requires(size_t uSize, const std::span<const uint8_t>vecBuffer, void*& pRegion, HANDLE & hObject)
    {
        { T::allocate(uSize, vecBuffer, pRegion, hObject) } -> std::convertible_to<bool>;
        { T::release(pRegion, hObject) } -> std::same_as<void>;
    };

    template<typename T>
    concept IsStubGenerationPolicy = requires(uint8_t * pBuffer, uint32_t uSyscallNumber, void* pGadget)
    {
        { T::bRequiresGadget } -> std::same_as<const bool&>;
        { T::getStubSize() } -> std::convertible_to<size_t>;
        { T::generate(pBuffer, uSyscallNumber, pGadget) } -> std::same_as<void>;
    };

    template<typename T>
    concept IsSyscallParsingPolicy = requires(const ModuleInfo_t & module)
    {
        { T::parse(module) } -> std::convertible_to<std::vector<SyscallEntry_t>>;
    };

    template<IsSyscallParsingPolicy... IParsers>
    struct ParserChain_t
    {
        static_assert(sizeof...(IParsers) > 0, "Parsedchain_t cannot be empty.");
    };

    template<
        typename IAllocationPolicy,
        typename IStubGenerationPolicy,
        typename IFirstParser,
        typename ... IFallbackParsers
    >
    class ManagerImpl
    {
    private:
        static_assert(IsIAllocationPolicy<IAllocationPolicy>,
            "[Syscall] The provided allocation policy is not valid. "
            "A valid allocation policy must provide two static functions: "
            "1. 'static bool allocate(size_t, const std::span<const uint8_t>, void*&, HANDLE&);' "
            "2. 'static void release(void*, HANDLE);'"
            );

        static_assert(IsStubGenerationPolicy<IStubGenerationPolicy>,
            "[Syscall] The provided stub generation policy is not valid. "
            "A valid stub generation policy must provide: "
            "1. A 'static constexpr bool bRequiresGadget' member. "
            "2. A 'static constexpr size_t getStubSize()' function. "
            "3. A 'static void generate(uint8_t*, uint32_t, void*)' function."
            );

        static_assert(IsSyscallParsingPolicy<IFirstParser> && (IsSyscallParsingPolicy<IFallbackParsers> && ...),
            "[Syscall] One or more provided syscall parsing policies are not valid. "
            "A valid parsing policy must provide a static function: "
            "1. 'static std::vector<SyscallEntry_t> parse(const ModuleInfo_t&);'"
            );

        std::mutex m_mutex;
        std::vector<SyscallEntry_t> m_vecParsedSyscalls;
        void* m_pSyscallRegion = nullptr;
        std::vector<void*> m_vecSyscallGadgets;
        size_t m_uRegionSize = 0;
        bool m_bInitialized = false;
        HANDLE m_hObjectHandle = nullptr;
        void* m_pVehHandle = nullptr;
    public:
        ManagerImpl() = default;
        ~ManagerImpl()
        {
            if constexpr (platform::isWindows64)
                if (m_pVehHandle)
                    RemoveVectoredExceptionHandler(m_pVehHandle);

            IAllocationPolicy::release(m_pSyscallRegion, m_hObjectHandle);
        }

        ManagerImpl(const ManagerImpl&) = delete;
        ManagerImpl& operator=(const ManagerImpl&) = delete;
        ManagerImpl(ManagerImpl&& other) noexcept
        {
            std::lock_guard<std::mutex> lock(other.m_mutex);
            m_vecParsedSyscalls = std::move(other.m_vecParsedSyscalls);
            m_pSyscallRegion = other.m_pSyscallRegion;
            m_vecSyscallGadgets = std::move(other.m_vecSyscallGadgets);
            m_uRegionSize = other.m_uRegionSize;
            m_bInitialized = other.m_bInitialized;
            m_hObjectHandle = other.m_hObjectHandle;
            other.m_pSyscallRegion = nullptr;
            other.m_hObjectHandle = nullptr;
        }

        ManagerImpl& operator=(ManagerImpl&& other) noexcept
        {
            if (this != &other)
            {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                IAllocationPolicy::release(m_pSyscallRegion, m_hObjectHandle);
                m_vecParsedSyscalls = std::move(other.m_vecParsedSyscalls);
                m_pSyscallRegion = other.m_pSyscallRegion;
                m_vecSyscallGadgets = std::move(other.m_vecSyscallGadgets);
                m_uRegionSize = other.m_uRegionSize;
                m_bInitialized = other.m_bInitialized;
                m_hObjectHandle = other.m_hObjectHandle;
                other.m_pSyscallRegion = nullptr;
                other.m_hObjectHandle = nullptr;
            }

            return *this;
        }

        [[nodiscard]] bool initialize(const std::vector<SyscallKey_t>& vecModuleKeys = { SYSCALL_ID("ntdll.dll") })
        {
            if (m_bInitialized)
                return true;

            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_bInitialized)
                return true;
#if SYSCALL_PLATFORM_WINDOWS_64
            if constexpr (IStubGenerationPolicy::bRequiresGadget)
                if (!findSyscallGadgets())
                    return false;
#endif

            m_vecParsedSyscalls.clear();
            for (const auto& moduleKey : vecModuleKeys)
            {
                ModuleInfo_t moduleInfo;
                if (!getModuleInfo(moduleKey, moduleInfo))
                    continue;

                std::vector<SyscallEntry_t> moduleSyscalls = tryParseSyscalls<IFirstParser, IFallbackParsers...>(moduleInfo);

                m_vecParsedSyscalls.insert(m_vecParsedSyscalls.end(), moduleSyscalls.begin(), moduleSyscalls.end());
            }

            if (m_vecParsedSyscalls.empty())
                return false;

            if (m_vecParsedSyscalls.size() > 1)
                for (size_t i = m_vecParsedSyscalls.size() - 1; i > 0; --i)
                    std::swap(m_vecParsedSyscalls[i], m_vecParsedSyscalls[native::rdtscp() % (i + 1)]);

            for (size_t i = 0; i < m_vecParsedSyscalls.size(); ++i)
                m_vecParsedSyscalls[i].m_uOffset = static_cast<uint32_t>(i * IStubGenerationPolicy::getStubSize());


            std::ranges::sort(m_vecParsedSyscalls, std::less{}, &SyscallEntry_t::m_key);

            m_bInitialized = createSyscalls();
            if (m_bInitialized)
            {
                if constexpr (std::is_same_v<IStubGenerationPolicy, policies::generator::exception>)
                {
                    m_pVehHandle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
                    if (!m_pVehHandle)
                    {
                        IAllocationPolicy::release(m_pSyscallRegion, m_hObjectHandle);
                        m_pSyscallRegion = nullptr;
                        m_bInitialized = false;
                    }
                }
            }

            return m_bInitialized;
        }
        template<typename Ret = uintptr_t, typename... Args>
        [[nodiscard]] SYSCALL_FORCE_INLINE Ret invoke(const SyscallKey_t& syscallId, Args... args)
        {
            if (!m_bInitialized)
            {
                if (!initialize())
                {
                    if constexpr (std::is_same_v<Ret, NTSTATUS>)
                        return native::STATUS_UNSUCCESSFUL;

                    return Ret{};
                }
            }
            auto it = std::ranges::lower_bound(m_vecParsedSyscalls, syscallId, std::less{}, &SyscallEntry_t::m_key);

            if (it == m_vecParsedSyscalls.end() || it->m_key != syscallId)
            {
                if constexpr (std::is_same_v<Ret, NTSTATUS>)
                    return native::STATUS_PROCEDURE_NOT_FOUND;

                return Ret{};
            }

            using Function_t = Ret(SYSCALL_API*)(Args...);

            uint8_t* pStubAddress = reinterpret_cast<uint8_t*>(m_pSyscallRegion) + it->m_uOffset;
            if constexpr (std::is_same_v<IStubGenerationPolicy, policies::generator::exception>)
            {
#if SYSCALL_PLATFORM_WINDOWS_64
                const size_t uGadgetCount = m_vecSyscallGadgets.size();

                if (!uGadgetCount)
                {
                    if constexpr (std::is_same_v<Ret, NTSTATUS>)
                        return native::STATUS_UNSUCCESSFUL;
                    return Ret{};
                }

                const size_t uRandomIndex = native::rdtscp() % uGadgetCount;
                void* pRandomGadget = m_vecSyscallGadgets[uRandomIndex];
#else
                void* pRandomGadget = (void*)__readfsdword(0xC0);
#endif

                CExceptionContextGuard contextGuard(pStubAddress, pRandomGadget, it->m_uSyscallNumber);
                return reinterpret_cast<Function_t>(pStubAddress)(std::forward<Args>(args)...);
            }

            return reinterpret_cast<Function_t>(pStubAddress)(std::forward<Args>(args)...);
        }
    private:
        template<IsSyscallParsingPolicy CurrentParser, IsSyscallParsingPolicy... OtherParsers>
        std::vector<SyscallEntry_t> tryParseSyscalls(const ModuleInfo_t& moduleInfo)
        {
            auto vecSyscalls = CurrentParser::parse(moduleInfo);

            if (!vecSyscalls.empty())
                return vecSyscalls;

            if constexpr (sizeof...(OtherParsers) > 0)
                return tryParseSyscalls<OtherParsers...>(moduleInfo);

            return vecSyscalls;
        }


        bool createSyscalls()
        {
            if (m_vecParsedSyscalls.empty())
                return false;
#if SYSCALL_PLATFORM_WINDOWS_64
            if constexpr (IStubGenerationPolicy::bRequiresGadget)
                if (m_vecSyscallGadgets.empty())
                    return false;
#endif

            m_uRegionSize = m_vecParsedSyscalls.size() * IStubGenerationPolicy::getStubSize();
            std::vector<uint8_t> vecTempBuffer(m_uRegionSize);

            const size_t uGadgetsCount = m_vecSyscallGadgets.size();

            for (const SyscallEntry_t& entry : m_vecParsedSyscalls)
            {
                uint8_t* pStubLocation = vecTempBuffer.data() + entry.m_uOffset;
                void* pGadgetForStub = nullptr;
#if SYSCALL_PLATFORM_WINDOWS_64
                if constexpr (IStubGenerationPolicy::bRequiresGadget)
                {
                    const size_t uRandomIndex = native::rdtscp() % uGadgetsCount;
                    pGadgetForStub = m_vecSyscallGadgets[uRandomIndex];
                }
#endif

                IStubGenerationPolicy::generate(pStubLocation, entry.m_uSyscallNumber, pGadgetForStub);
            }

            return IAllocationPolicy::allocate(m_uRegionSize, vecTempBuffer, m_pSyscallRegion, m_hObjectHandle);
        }

        bool getModuleInfo(SyscallKey_t moduleKey, ModuleInfo_t& info)
        {
            HMODULE hModule = native::getModuleBase(moduleKey);
            if (!hModule)
                return false;

            info.m_pModuleBase = reinterpret_cast<uint8_t*>(hModule);

            auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(info.m_pModuleBase);
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            info.m_pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(info.m_pModuleBase + pDosHeader->e_lfanew);
            if (info.m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                return false;

            auto uExportRva = info.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!uExportRva)
                return false;

            info.m_pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(info.m_pModuleBase + uExportRva);

            return true;
        }

#if SYSCALL_PLATFORM_WINDOWS_64
        bool findSyscallGadgets()
        {
            ModuleInfo_t ntdll;
            if (!getModuleInfo(SYSCALL_ID("ntdll.dll"), ntdll))
                return false;

            IMAGE_SECTION_HEADER* pSections = IMAGE_FIRST_SECTION(ntdll.m_pNtHeaders);
            uint8_t* pTextSection = nullptr;
            uint32_t uTextSectionSize = 0;
            for (int i = 0; i < ntdll.m_pNtHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (hashing::calculateHashRuntime(reinterpret_cast<const char*>(pSections[i].Name)) == hashing::calculateHash(".text"))
                {
                    pTextSection = ntdll.m_pModuleBase + pSections[i].VirtualAddress;
                    uTextSectionSize = pSections[i].Misc.VirtualSize;
                    break;
                }
            }

            if (!pTextSection || !uTextSectionSize)
                return false;

            m_vecSyscallGadgets.clear();
            for (DWORD i = 0; i < uTextSectionSize - 2; ++i)
                if (pTextSection[i] == 0x0F && pTextSection[i + 1] == 0x05 && pTextSection[i + 2] == 0xC3)
                    m_vecSyscallGadgets.push_back(&pTextSection[i]);

            return !m_vecSyscallGadgets.empty();
        }
#endif

    };
}

#include "aliases.hpp"

#endif  

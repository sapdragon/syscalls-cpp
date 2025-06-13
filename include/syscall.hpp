#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <fstream>
#include <mutex>
#include <cstring>
#include <utility>
#include <concepts> 
#include <array>
#include <random>
#include <algorithm>

#include "shared.hpp"
#include "hash.hpp"
#include "native_api.hpp"

namespace syscall
{

    thread_local struct ExceptionContext_t
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

    LONG NTAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
    {
        if (!pExceptionContext.m_bShouldHandle)
            return EXCEPTION_CONTINUE_SEARCH;

        if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
            pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionContext.m_pExpectedExceptionAddress)
        {
            pExceptionContext.m_bShouldHandle = false;

            pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx;
            pExceptionInfo->ContextRecord->Rax = pExceptionContext.m_uSyscallNumber;
            pExceptionInfo->ContextRecord->Rip = reinterpret_cast<uintptr_t>(pExceptionContext.m_pSyscallGadget);

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    namespace policies
    {
        struct SectionAllocator
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/)
            {
                HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));

                auto fNtCreateSection = reinterpret_cast<NtCreateSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtCreateSection")));
                auto fNtMapView = reinterpret_cast<NtMapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtMapViewOfSection")));
                auto fNtUnmapView = reinterpret_cast<NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                auto fNtClose = reinterpret_cast<NtCloseHandle_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtClose")));
                if (!fNtCreateSection || !fNtMapView || !fNtUnmapView || !fNtClose)
                    return false;

                HANDLE hSectionHandle = nullptr;
                LARGE_INTEGER sectionSize;
                sectionSize.QuadPart = uRegionSize;

                NTSTATUS status = fNtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, nullptr, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, nullptr);
                if (!NT_SUCCESS(status))
                    return false;

                void* pTempView = nullptr;
                SIZE_T uViewSize = uRegionSize;
                status = fNtMapView(hSectionHandle, NtCurrentProcess(), &pTempView, 0, 0, nullptr, &uViewSize, ViewShare, 0, PAGE_READWRITE);
                if (!NT_SUCCESS(status))
                {
                    fNtClose(hSectionHandle);
                    return false;
                }

                crt::memory::copy(pTempView, vecBuffer.data(), uRegionSize);
                fNtUnmapView(NtCurrentProcess(), pTempView);
                uViewSize = uRegionSize;
                status = fNtMapView(hSectionHandle, NtCurrentProcess(), &pOutRegion, 0, 0, nullptr, &uViewSize, ViewShare, 0, PAGE_EXECUTE_READ);
                fNtClose(hSectionHandle);
                return NT_SUCCESS(status) && pOutRegion;
            }
            static void release(void* pRegion, HANDLE /*hHeapHandle*/)
            {
                HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
                if (pRegion)
                {
                    auto fNtUnmapView = reinterpret_cast<NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                    if (fNtUnmapView)
                        fNtUnmapView(NtCurrentProcess(), pRegion);
                }
            }
        };

        struct HeapAllocator
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& hOutHeapHandle)
            {
                using RtlGetLastNtStatus_t = NTSTATUS(NTAPI*)();
                HMODULE hNtdll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
                if (!hNtdll)
                    return false;

                auto fRtlCreateHeap = reinterpret_cast<RtlCreateHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlCreateHeap")));
                auto fRtlAllocateHeap = reinterpret_cast<RtlAllocateHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlAllocateHeap")));
                auto fRtlGetLastNtStatus = reinterpret_cast<RtlGetLastNtStatus_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlGetLastNtStatus")));
                if (!fRtlCreateHeap || !fRtlAllocateHeap)
                    return false;

                hOutHeapHandle = fRtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE, nullptr, 0, 0, nullptr, nullptr);
                if (!hOutHeapHandle)
                    return false;

                pOutRegion = fRtlAllocateHeap(hOutHeapHandle, 0, uRegionSize);
                if (!pOutRegion)
                {
                    release(nullptr, hOutHeapHandle);
                    hOutHeapHandle = nullptr;
                    return false;
                }

                crt::memory::copy(pOutRegion, vecBuffer.data(), uRegionSize);
                return true;
            }

            static void release(void* /*region*/, HANDLE hHeapHandle)
            {
                if (hHeapHandle)
                {
                    HMODULE hNtdll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
                    if (!hNtdll)
                        return;

                    auto fRtlDestroyHeap = reinterpret_cast<RtlDestroyHeap_t>(native::getExportAddress(hNtdll, SYSCALL_ID("RtlDestroyHeap")));
                    if (fRtlDestroyHeap)
                        fRtlDestroyHeap(hHeapHandle);
                }
            }
        };

        struct VirtualMemoryAllocator
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/)
            {
                HMODULE hNtDll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));

                auto fNtAllocate = reinterpret_cast<NtAllocateVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtAllocateVirtualMemory")));
                auto fNtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtProtectVirtualMemory")));
                if (!fNtAllocate || !fNtProtect)
                    return false;

                pOutRegion = nullptr;
                SIZE_T uSize = uRegionSize;
                NTSTATUS status = fNtAllocate(NtCurrentProcess(), &pOutRegion, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (!NT_SUCCESS(status) || !pOutRegion)
                    return false;

                crt::memory::copy(pOutRegion, vecBuffer.data(), uRegionSize);

                ULONG oldProtection = 0;
                uSize = uRegionSize;
                status = fNtProtect(NtCurrentProcess(), &pOutRegion, &uSize, PAGE_EXECUTE_READ, &oldProtection);

                if (!NT_SUCCESS(status))
                {
                    uSize = 0;
                    fNtAllocate(NtCurrentProcess(), &pOutRegion, 0, &uSize, MEM_RELEASE, 0);
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
                    auto fNtFree = reinterpret_cast<NtFreeVirtualMemory_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtFreeVirtualMemory")));
                    if (fNtFree)
                    {
                        SIZE_T uSize = 0;
                        fNtFree(NtCurrentProcess(), &pRegion, &uSize, MEM_RELEASE);
                    }
                }
            }
        };

        struct GadgetStubGenerator
        {
            static constexpr bool bRequiresGadget = true;
            static constexpr size_t getStubSize() { return 32; }
            static void generate(uint8_t* pBuffer, uint32_t uSyscallNumber, void* pGadgetAddress)
            {
                // @note / SapDragon: mov r10, rcx
                pBuffer[0] = 0x49;
                pBuffer[1] = 0x89;
                pBuffer[2] = 0xCA;

                // @note / SapDragon: mov eax, syscallNumber
                pBuffer[3] = 0xB8;
                *reinterpret_cast<uint32_t*>(&pBuffer[4]) = uSyscallNumber;

                // @note / SapDragon: mov r11, gadgetAddress
                pBuffer[8] = 0x49;
                pBuffer[9] = 0xBB;
                *reinterpret_cast<uint64_t*>(&pBuffer[10]) = reinterpret_cast<uint64_t>(pGadgetAddress);

                // @note / SapDragon: push r11
                pBuffer[18] = 0x41;
                pBuffer[19] = 0x53;

                // @note / SapDragon: ret
                pBuffer[20] = 0xC3;
            }
        };

        struct DirectStubGenerator
        {
            static constexpr bool bRequiresGadget = false;

            inline static constexpr std::array<uint8_t, 18> arrShellcode =
            {
                0x51,                               // push rcx
                0x41, 0x5A,                         // pop r10
                0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0x00000000 (syscall number placeholder)
                0x0F, 0x05,                         // syscall
                0x48, 0x83, 0xC4, 0x08,             // add rsp, 8
                0xFF, 0x64, 0x24, 0xF8              // jmp qword ptr [rsp-8]
            };

            static constexpr size_t getStubSize() { return arrShellcode.size(); }

            static void generate(uint8_t* pBuffer, uint32_t uSyscallNumber, void* /*pGadgetAddress*/)
            {
                crt::memory::copy(pBuffer, arrShellcode.data(), arrShellcode.size());
                *reinterpret_cast<uint32_t*>(pBuffer + 4) = uSyscallNumber;
            }
        };


        struct ExceptionStubGenerator
        {
            static constexpr bool bRequiresGadget = true;
            static constexpr size_t getStubSize() { return 8; }
            static void generate(uint8_t* pBuffer, uint32_t /*uSyscallNumber*/, void* /*pGadgetAddress*/)
            {
                pBuffer[0] = 0x0F;
                pBuffer[1] = 0x0B;
                pBuffer[2] = 0xC3;
                crt::memory::set(pBuffer + 2, 0x90, getStubSize() - 3);
            }
        };
    }

    template<typename T>
    concept IsIAllocationPolicy = requires(size_t uSize, const std::vector<uint8_t>&vecBuffer, void*& pRegion, HANDLE & hObject)
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

    struct ModuleInfo_t
    {
        uint8_t* m_pModuleBase = nullptr;
        IMAGE_NT_HEADERS* m_pNtHeaders = nullptr;
        IMAGE_EXPORT_DIRECTORY* m_pExportDir = nullptr;
    };


    template<IsIAllocationPolicy IAllocationPolicy, IsStubGenerationPolicy IStubGenerationPolicy>
    class Manager
    {
    private:
        std::mutex m_mutex;
        std::vector<SyscallEntry_t> m_vecParsedSyscalls;
        void* m_pSyscallRegion = nullptr;
        std::vector<void*> m_vecSyscallGadgets;
        size_t m_uRegionSize = 0;
        bool m_bInitialized = false;
        HANDLE m_hObjectHandle = nullptr;
        void* m_pVehHandle = nullptr;
    public:
        Manager() = default;
        ~Manager()
        {
            if (m_pVehHandle)
                RemoveVectoredExceptionHandler(m_pVehHandle);

            IAllocationPolicy::release(m_pSyscallRegion, m_hObjectHandle);
        }

        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&& other) noexcept
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

        Manager& operator=(Manager&& other) noexcept
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

        bool initialize(const std::vector<SyscallKey_t>& vecModuleKeys = {SYSCALL_ID("ntdll.dll")})
        {
            if (m_bInitialized)
                return true;

            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_bInitialized)
                return true;

            if constexpr (IStubGenerationPolicy::bRequiresGadget)
                if (!findSyscallGadgets())
                    return false;

            m_vecParsedSyscalls.clear();
            for (const auto& moduleKey : vecModuleKeys)
            {
                ModuleInfo_t moduleInfo;
                if (!getModuleInfo(moduleKey, moduleInfo))
                    continue; 

                std::vector<SyscallEntry_t> moduleSyscalls = extractSyscallsFromExceptionDir(moduleInfo);

                if (moduleSyscalls.empty())
                    moduleSyscalls = extractSyscallsByScanning(moduleInfo);

                m_vecParsedSyscalls.insert(m_vecParsedSyscalls.end(), moduleSyscalls.begin(), moduleSyscalls.end());
            }

            if (m_vecParsedSyscalls.empty())
                return false;

            std::sort(m_vecParsedSyscalls.begin(), m_vecParsedSyscalls.end(),
                [](const SyscallEntry_t& a, const SyscallEntry_t& b) {
                    return a.m_key < b.m_key;
                });

            for (size_t i = 0; i < m_vecParsedSyscalls.size(); ++i)
                m_vecParsedSyscalls[i].m_uOffset = static_cast<uint32_t>(i * IStubGenerationPolicy::getStubSize());

            m_bInitialized = createSyscalls();
            if (m_bInitialized)
            {
                if constexpr (std::is_same_v<IStubGenerationPolicy, policies::ExceptionStubGenerator>)
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
        template<typename Ret, typename... Args>
        SYSCALL_FORCE_INLINE Ret invoke(const SyscallKey_t& syscallId, Args... args)
        {
            if (!m_bInitialized)
            {
                if (!initialize())
                {
                    if constexpr (std::is_same_v<Ret, NTSTATUS>)
                        return STATUS_UNSUCCESSFUL;

                    return Ret{};
                }
            }
            auto it = std::lower_bound(m_vecParsedSyscalls.begin(), m_vecParsedSyscalls.end(), syscallId,
                [](const SyscallEntry_t& entry, const SyscallKey_t& id) {
                    return entry.m_key < id;
                });

            if (it == m_vecParsedSyscalls.end() || it->m_key != syscallId)
            {
                if constexpr (std::is_same_v<Ret, NTSTATUS>)
                    return STATUS_PROCEDURE_NOT_FOUND;
                return Ret{};
            }

            using Function_t = Ret(NTAPI*)(Args...);

            uint8_t* pStubAddress = reinterpret_cast<uint8_t*>(m_pSyscallRegion) + it->m_uOffset;

            if constexpr (std::is_same_v<IStubGenerationPolicy, policies::ExceptionStubGenerator>)
            {
                const size_t uGadgetCount = m_vecSyscallGadgets.size();

                if (!uGadgetCount)
                {
                    if constexpr (std::is_same_v<Ret, NTSTATUS>)
                        return STATUS_UNSUCCESSFUL;
                    return Ret{};
                }

                const size_t uRandomIndex = native::rdtscp() % uGadgetCount;
                void* pRandomGadget = m_vecSyscallGadgets[uRandomIndex];

                CExceptionContextGuard contextGuard(pStubAddress, pRandomGadget, it->m_uSyscallNumber);
                return reinterpret_cast<Function_t>(pStubAddress)(std::forward<Args>(args)...);
            }
            else
            {
                return reinterpret_cast<Function_t>(pStubAddress)(std::forward<Args>(args)...);
            }
        }
    private:
        bool createSyscalls()
        {
            if (m_vecParsedSyscalls.empty())
                return false;

            if constexpr (IStubGenerationPolicy::bRequiresGadget)
                if (m_vecSyscallGadgets.empty())
                    return false;

            m_uRegionSize = m_vecParsedSyscalls.size() * IStubGenerationPolicy::getStubSize();
            std::vector<uint8_t> vecTempBuffer(m_uRegionSize);

            const size_t uGadgetsCount = m_vecSyscallGadgets.size();

            for (const SyscallEntry_t& entry : m_vecParsedSyscalls) 
            {
                uint8_t* pStubLocation = vecTempBuffer.data() + entry.m_uOffset;
                void* pGadgetForStub = nullptr;

                if constexpr (IStubGenerationPolicy::bRequiresGadget) 
                {
                    const size_t uRandomIndex = native::rdtscp() % uGadgetsCount;
                    pGadgetForStub = m_vecSyscallGadgets[uRandomIndex];
                }

                IStubGenerationPolicy::generate(pStubLocation, entry.m_uSyscallNumber, pGadgetForStub);
            }

            return IAllocationPolicy::allocate(m_uRegionSize, vecTempBuffer, m_pSyscallRegion, m_hObjectHandle);
        }

        struct NtdllInfo_t
        {
            uint8_t* m_pNtdllBase = nullptr;
            IMAGE_NT_HEADERS* m_pNtHeaders = nullptr;
            IMAGE_EXPORT_DIRECTORY* m_pExportDir = nullptr;
        };

        static bool getNtdll(NtdllInfo_t& info)
        {
            HMODULE hNtdll = native::getModuleBase(hashing::calculateHash("ntdll.dll"));
            if (!hNtdll)
                return false;

            info.m_pNtdllBase = reinterpret_cast<uint8_t*>(hNtdll);

            auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(info.m_pNtdllBase);
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            info.m_pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(info.m_pNtdllBase + pDosHeader->e_lfanew);
            if (info.m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                return false;

            auto uExportRva = info.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!uExportRva)
                return false;

            info.m_pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(info.m_pNtdllBase + uExportRva);

            return true;
        }

        std::vector<SyscallEntry_t> extractSyscallsFromExceptionDir(const ModuleInfo_t& module)
        {
            std::vector<SyscallEntry_t> vecFoundSyscalls;

            auto uExceptionDirRva = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            if (!uExceptionDirRva)
                return vecFoundSyscalls;

            auto pRuntimeFunctions = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(module.m_pModuleBase + uExceptionDirRva);
            auto uExceptionDirSize = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
            auto uFunctionCount = uExceptionDirSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNameOrdinals);

            std::unordered_map<uint32_t, const char*> mapRvaToName;
            for (uint32_t i = 0; i < module.m_pExportDir->NumberOfNames; ++i)
            {
                const char* szName = reinterpret_cast<const char*>(module.m_pModuleBase + pNamesRVA[i]);
                uint16_t uOrdinal = pOrdinalsRva[i];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];
                mapRvaToName[uFunctionRva] = szName;
            }

            uint32_t uSyscallNumber = 0; 
            for (DWORD i = 0; i < uFunctionCount; ++i)
            {
                auto pFunction = &pRuntimeFunctions[i];
                if (pFunction->BeginAddress == 0)
                    break; 

                auto it = mapRvaToName.find(pFunction->BeginAddress);
                if (it != mapRvaToName.end())
                {
                    const char* szName = it->second;

                    if (hashing::calculateHashRuntime(szName, 2) == hashing::calculateHash("Zw"))
                    {
                        char szNtName[128];
                        crt::string::copy(szNtName,128, szName);
                        szNtName[0] = 'N';
                        szNtName[1] = 't';

                        const SyscallKey_t key = SYSCALL_ID_RT(szNtName);

                        vecFoundSyscalls.push_back(SyscallEntry_t{
                                    key,
                                    uSyscallNumber,
                                    0 
                            });
                        uSyscallNumber++;
                    }
                }
            }

            return vecFoundSyscalls;
        }

        std::vector<SyscallEntry_t> extractSyscallsByScanning(const ModuleInfo_t& module)
        {
            std::vector<SyscallEntry_t> vecFoundSyscalls;

            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(module.m_pModuleBase + module.m_pExportDir->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < module.m_pExportDir->NumberOfNames; i++)
            {
                const char* szName = reinterpret_cast<const char*>(module.m_pModuleBase + pNamesRVA[i]);

                if (hashing::calculateHashRuntime(szName, 2) != hashing::calculateHash("Nt"))
                    continue;

                uint16_t uOrdinal = pOrdinalsRva[i];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];

                auto pExportSectionStart = module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                auto pExportSectionEnd = pExportSectionStart + module.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                if (uFunctionRva >= pExportSectionStart && uFunctionRva < pExportSectionEnd)
                    continue;

                uint8_t* pFunctionStart = module.m_pModuleBase + uFunctionRva;
                uint32_t uSyscallNumber = 0;

                bool bIsHooked = false;

                // @note / SapDragon: 0xB8D18B4C disasm
                // mov r10, rcx; mov eax, syscall_number
                // mov r10, rcx
                // mov eax, imm32
                if (*reinterpret_cast<uint32_t*>(pFunctionStart) == 0xB8D18B4C)
                    uSyscallNumber = *reinterpret_cast<uint32_t*>(pFunctionStart + 4);
                else if (isFunctionHooked(pFunctionStart))
                    bIsHooked = true;

                if (bIsHooked)
                {
                    // @note / SapDragon: search up
                    for (int j = 1; j < 20; ++j)
                    {
                        uint8_t* pNeighborFunc = pFunctionStart - (j * 0x20);
                        if (reinterpret_cast<uintptr_t>(pNeighborFunc) < reinterpret_cast<uintptr_t>(module.m_pModuleBase)) break;
                        if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                        {
                            uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                            uSyscallNumber = uNeighborSyscall + j;
                            break;
                        }
                    }

                    // @note / SapDragon: search down
                    if (!uSyscallNumber)
                    {
                        for (int j = 1; j < 20; ++j)
                        {
                            uint8_t* pNeighborFunc = pFunctionStart + (j * 0x20);
                            if (reinterpret_cast<uintptr_t>(pNeighborFunc) > (reinterpret_cast<uintptr_t>(module.m_pModuleBase) + module.m_pNtHeaders->OptionalHeader.SizeOfImage)) break;
                            if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                            {
                                uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                                uSyscallNumber = uNeighborSyscall - j;
                                break;
                            }
                        }
                    }
                }

                if (uSyscallNumber)
                {
                    const SyscallKey_t key = SYSCALL_ID_RT(szName);
                    vecFoundSyscalls.push_back(SyscallEntry_t{
                                key,
                                uSyscallNumber,
                                0
                        });
                }
            }
            return vecFoundSyscalls;
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


        bool findSyscallGadgets()
        {
            NtdllInfo_t ntdll;
            if (!getNtdll(ntdll))
                return false;

            IMAGE_SECTION_HEADER* pSections = IMAGE_FIRST_SECTION(ntdll.m_pNtHeaders);
            uint8_t* pTextSection = nullptr;
            uint32_t uTextSectionSize = 0;
            for (int i = 0; i < ntdll.m_pNtHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (hashing::calculateHashRuntime(reinterpret_cast<const char*>(pSections[i].Name)) == hashing::calculateHash(".text"))
                {
                    pTextSection = ntdll.m_pNtdllBase + pSections[i].VirtualAddress;
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

        bool isFunctionHooked(const uint8_t* pFunctionStart) const
        {
            const uint8_t* pCurrent = pFunctionStart;

            while (*pCurrent == 0x90)
                pCurrent++;

            switch (pCurrent[0])
            {
                // @note / SapDragon: JMP rel32
            case 0xE9:
                // @note / SapDragon: JMP rel8
            case 0xEB:
                // @note / SapDragon: push imm32
            case 0x68:
                return true;
                // @note / SapDragon: jmp [mem] / jmp [rip + offset]
            case 0xFF:
                if (pCurrent[1] == 0x25)
                    return true;
                break;

                // @note / SapDragon: int3...
            case 0xCC:
                return true;

            default:
                break;
            }

            return false;
        }
    };
}

using SyscallSectionGadget = syscall::Manager<syscall::policies::SectionAllocator, syscall::policies::GadgetStubGenerator>;
using SyscallHeapGadget = syscall::Manager<syscall::policies::HeapAllocator, syscall::policies::GadgetStubGenerator>;
using SyscallSectionDirect = syscall::Manager<syscall::policies::SectionAllocator, syscall::policies::DirectStubGenerator>;

#endif 
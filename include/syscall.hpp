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

#include "shared.hpp"
#include "native_api.hpp"

namespace syscall 
{
    namespace policies 
    {
        struct SectionAllocator 
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/) 
            {
                HMODULE hNtDll = native::getModuleBase(L"ntdll.dll");

                auto fNtCreateSection = reinterpret_cast<NtCreateSection_t>(native::getExportAddress(hNtDll, "NtCreateSection"));
                auto fNtMapView = reinterpret_cast<NtMapViewOfSection_t>(native::getExportAddress(hNtDll, "NtMapViewOfSection"));
                auto fNtUnmapView = reinterpret_cast<NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, "NtUnmapViewOfSection"));
                if (!fNtCreateSection || !fNtMapView || !fNtUnmapView) 
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
                    CloseHandle(hSectionHandle);
                    return false; 
                }

                memcpy(pTempView, vecBuffer.data(), uRegionSize);
                fNtUnmapView(NtCurrentProcess(), pTempView);
                uViewSize = uRegionSize;
                status = fNtMapView(hSectionHandle, NtCurrentProcess(), &pOutRegion, 0, 0, nullptr, &uViewSize, ViewShare, 0, PAGE_EXECUTE_READ);
                CloseHandle(hSectionHandle);
                return NT_SUCCESS(status) && pOutRegion;
            }
            static void release(void* pRegion, HANDLE /*hHeapHandle*/) 
            {
                HMODULE hNtDll = native::getModuleBase(L"ntdll.dll");
                if (pRegion) 
                {
                    auto fNtUnmapView = reinterpret_cast<NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, "NtUnmapViewOfSection"));
                    if (fNtUnmapView) 
                        fNtUnmapView(NtCurrentProcess(), pRegion);
                }
            }
        };

        struct HeapAllocator
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& hOutHeapHandle)
            {
                HMODULE hNtdll = native::getModuleBase(L"ntdll.dll");
                if (!hNtdll)
                    return false;

                auto fRtlCreateHeap = reinterpret_cast<RtlCreateHeap_t>(native::getExportAddress(hNtdll, "RtlCreateHeap"));
                auto fRtlAllocateHeap = reinterpret_cast<RtlAllocateHeap_t>(native::getExportAddress(hNtdll, "RtlAllocateHeap"));

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

                memcpy(pOutRegion, vecBuffer.data(), uRegionSize);
                return true;
            }

            static void release(void* /*region*/, HANDLE hHeapHandle)
            {
                if (hHeapHandle)
                {
                    HMODULE hNtdll = native::getModuleBase(L"ntdll.dll");
                    if (!hNtdll)
                        return;

                    auto fRtlDestroyHeap = reinterpret_cast<RtlDestroyHeap_t>(native::getExportAddress(hNtdll, "RtlDestroyHeap"));
                    if (fRtlDestroyHeap)
                        fRtlDestroyHeap(hHeapHandle);
                }
            }
        };

        struct VirtualMemoryAllocator 
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/) 
            {
                HMODULE hNtDll = native::getModuleBase(L"ntdll.dll");

                auto fNtAllocate = reinterpret_cast<NtAllocateVirtualMemory_t>(native::getExportAddress(hNtDll, "NtAllocateVirtualMemory"));
                auto fNtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(native::getExportAddress(hNtDll, "NtProtectVirtualMemory"));
                if (!fNtAllocate || !fNtProtect) 
                    return false;

                pOutRegion = nullptr;
                SIZE_T uSize = uRegionSize;
                NTSTATUS status = fNtAllocate(NtCurrentProcess(), &pOutRegion, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (!NT_SUCCESS(status) || !pOutRegion)
                    return false;

                memcpy(pOutRegion, vecBuffer.data(), uRegionSize);

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
                HMODULE hNtDll = native::getModuleBase(L"ntdll.dll");

                if (pRegion) 
                {
                    auto fNtFree = reinterpret_cast<NtFreeVirtualMemory_t>(native::getExportAddress(hNtDll, "NtFreeVirtualMemory"));
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
                memcpy(pBuffer, arrShellcode.data(), arrShellcode.size());
                *reinterpret_cast<uint32_t*>(pBuffer + 4) = uSyscallNumber;
            }
        };
    }

    template<typename T>
    concept IsIAllocationPolicy = requires(size_t uSize, const std::vector<uint8_t>& vecBuffer, void*& pRegion, HANDLE & hObject) 
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

    struct SyscallEntry_t 
    {
        std::string m_sName;
        uint32_t m_uSyscallNumber;
        uint32_t m_uOffset;
    };

    template<IsIAllocationPolicy IAllocationPolicy, IsStubGenerationPolicy IStubGenerationPolicy>
    class Manager 
    {
    private:
        std::mutex m_mutex;
        std::unordered_map<std::string, SyscallEntry_t> m_mapParsedSyscalls;
        void* m_pSyscallRegion = nullptr;
        void* m_pSyscallGadget = nullptr;
        size_t m_uRegionSize = 0;
        bool m_bInitialized = false;
        HANDLE m_hObjectHandle = nullptr;
    public:
        Manager() = default;
        ~Manager() 
        {
            IAllocationPolicy::release(m_pSyscallRegion, m_hObjectHandle); 
        }

        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&& other) noexcept 
        {
            std::lock_guard<std::mutex> lock(other.m_mutex);
            m_mapParsedSyscalls = std::move(other.m_mapParsedSyscalls);
            m_pSyscallRegion = other.m_pSyscallRegion;
            m_pSyscallGadget = other.m_pSyscallGadget;
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
                m_mapParsedSyscalls = std::move(other.m_mapParsedSyscalls);
                m_pSyscallRegion = other.m_pSyscallRegion;
                m_pSyscallGadget = other.m_pSyscallGadget;
                m_uRegionSize = other.m_uRegionSize;
                m_bInitialized = other.m_bInitialized;
                m_hObjectHandle = other.m_hObjectHandle;
                other.m_pSyscallRegion = nullptr;
                other.m_hObjectHandle = nullptr;
            }

            return *this;
        }

        bool initialize() 
        {
            if (m_bInitialized)
                return true;

            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_bInitialized)
                return true;

            if constexpr (IStubGenerationPolicy::bRequiresGadget)
                if (!findSyscallGadget())
                    return false;

            if (!extractSyscallsFromExceptionDir())
            {
                // @note / SapDragon: fallback if the primary one fails
                m_mapParsedSyscalls.clear();
                if (!extractSyscallsByScanning())
                    return false; 
            }

            m_bInitialized = createSyscalls();
            return m_bInitialized;
        }

        template<typename Ret, typename... Args>
        SYSCALL_FORCE_INLINE Ret invoke(const std::string& sSyscallName, Args... args)
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
            auto it = m_mapParsedSyscalls.find(sSyscallName);
            if (it == m_mapParsedSyscalls.end()) 
            {
                if constexpr (std::is_same_v<Ret, NTSTATUS>) 
                    return STATUS_PROCEDURE_NOT_FOUND;

                return Ret{};
            }

            using Function_t = Ret(NTAPI*)(Args...);
            uint8_t* pStubAddress = reinterpret_cast<uint8_t*>(m_pSyscallRegion) + it->second.m_uOffset;
            auto fStub = reinterpret_cast<Function_t>(pStubAddress);
            return fStub(std::forward<Args>(args)...);
        }
    private:
        bool createSyscalls() 
        {
            if (m_mapParsedSyscalls.empty()) 
                return false;

            if constexpr (IStubGenerationPolicy::bRequiresGadget) 
                if (!m_pSyscallGadget) 
                    return false;

            m_uRegionSize = m_mapParsedSyscalls.size() * IStubGenerationPolicy::getStubSize();
            std::vector<uint8_t> vecTempBuffer(m_uRegionSize);
            for (const auto& syscallPair : m_mapParsedSyscalls) {
                const SyscallEntry_t& entry = syscallPair.second;
                uint8_t* stubLocation = vecTempBuffer.data() + entry.m_uOffset;
                IStubGenerationPolicy::generate(stubLocation, entry.m_uSyscallNumber, m_pSyscallGadget);
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
            HMODULE hNtdll = native::getModuleBase(L"ntdll.dll");
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

        bool extractSyscallsFromExceptionDir()
        {
            NtdllInfo_t ntdll;
            if (!getNtdll(ntdll))
                return false;

            auto uExceptionDirRva = ntdll.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            if (!uExceptionDirRva)
                return false;

            auto pRuntimeFunctions = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(ntdll.m_pNtdllBase + uExceptionDirRva);
            auto uExceptionDirSize = ntdll.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
            auto uFunctionCount = uExceptionDirSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfNameOrdinals);

            std::unordered_map<uint32_t, const char*> mapRvaToName;
            for (uint32_t iCurrentNameIndex = 0; iCurrentNameIndex < ntdll.m_pExportDir->NumberOfNames; ++iCurrentNameIndex)
            {
                const char* szName = reinterpret_cast<const char*>(ntdll.m_pNtdllBase + pNamesRVA[iCurrentNameIndex]);
                uint16_t uOrdinal = pOrdinalsRva[iCurrentNameIndex];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];
                mapRvaToName[uFunctionRva] = szName;
            }

            uint32_t uSyscallNumber = 0;
            for (DWORD iCurrentFunctionIndex = 0; iCurrentFunctionIndex < uFunctionCount; ++iCurrentFunctionIndex)
            {
                auto pFunction = &pRuntimeFunctions[iCurrentFunctionIndex];
                if (pFunction->BeginAddress == 0)
                    break;

                auto it = mapRvaToName.find(pFunction->BeginAddress);
                if (it != mapRvaToName.end())
                {
                    const char* szName = it->second;
                    if (szName[0] == 'Z' && szName[1] == 'w')
                    {
                        std::string sName = szName;
                        sName[0] = 'N';
                        sName[1] = 't';

                        m_mapParsedSyscalls[sName] = SyscallEntry_t{
                             sName,
                             uSyscallNumber,
                             static_cast<uint32_t>(m_mapParsedSyscalls.size() * IStubGenerationPolicy::getStubSize())
                        };
                        uSyscallNumber++;
                    }
                }
            }

            return !m_mapParsedSyscalls.empty();
        }

        bool extractSyscallsByScanning()
        {
            NtdllInfo_t ntdll;
            if (!getNtdll(ntdll))
                return false;

            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(ntdll.m_pNtdllBase + ntdll.m_pExportDir->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < ntdll.m_pExportDir->NumberOfNames; i++)
            {
                const char* szName = reinterpret_cast<const char*>(ntdll.m_pNtdllBase + pNamesRVA[i]);

                if (strncmp(szName, "Nt", 2) != 0)
                    continue;

                uint16_t uOrdinal = pOrdinalsRva[i];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];
                auto pExportSectionStart = ntdll.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                auto pExportSectionEnd = pExportSectionStart + ntdll.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                if (uFunctionRva >= pExportSectionStart && uFunctionRva < pExportSectionEnd)
                    continue;

                uint8_t* pFunctionStart = ntdll.m_pNtdllBase + uFunctionRva;
                uint32_t uSyscallNumber = 0;

                bool bIsHooked = false;
                // @note / SapDragon: mov r10, rcx; mov eax, syscallNumber
                if (*reinterpret_cast<uint32_t*>(pFunctionStart) == 0xB8D18B4C) 
                    uSyscallNumber = *reinterpret_cast<uint32_t*>(pFunctionStart + 4);
                else if (isFunctionHooked(pFunctionStart))
                    bIsHooked = true;

                if (bIsHooked)
                {
                    // @note / SapDragon: search up
                    for (int j = 1; j < 20; ++j)
                    {
                        uint8_t* pNeighborFunc = pFunctionStart + (j * 0x20);
                        if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                        {
                            uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                            uSyscallNumber = uNeighborSyscall - j;
                            break;
                        }
                    }

                    // @note / SapDragon: search down
                    if (!uSyscallNumber)
                    {
                        for (int j = 1; j < 20; ++j)
                        {
                            uint8_t* pNeighborFunc = pFunctionStart - (j * 0x20);
                            if (*reinterpret_cast<uint32_t*>(pNeighborFunc) == 0xB8D18B4C)
                            {
                                uint32_t uNeighborSyscall = *reinterpret_cast<uint32_t*>(pNeighborFunc + 4);
                                uSyscallNumber = uNeighborSyscall + j;
                                break;
                            }
                        }
                    }
                }

                if (uSyscallNumber)
                {
                    std::string sName = szName;
                    m_mapParsedSyscalls[sName] = SyscallEntry_t
                    {
                         sName,
                         uSyscallNumber,
                         static_cast<uint32_t>((m_mapParsedSyscalls.size() * IStubGenerationPolicy::getStubSize()))
                    };
                }
            }
            return !m_mapParsedSyscalls.empty();
        }

        bool findSyscallGadget()
        {
            NtdllInfo_t ntdll;
            if (!getNtdll(ntdll))
                return false;

            IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntdll.m_pNtHeaders);
            uint8_t* pTextSection = nullptr;
            uint32_t uTextSectionSize = 0;
            for (int i = 0; i < ntdll.m_pNtHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (strcmp(reinterpret_cast<char*>(sections[i].Name), ".text") == 0)
                {
                    pTextSection = ntdll.m_pNtdllBase + sections[i].VirtualAddress;
                    uTextSectionSize = sections[i].Misc.VirtualSize;
                    break;
                }
            }

            if (!pTextSection || !uTextSectionSize)
                return false;

            for (DWORD i = 0; i < uTextSectionSize - 2; ++i)
            {
                if (pTextSection[i] == 0x0F && pTextSection[i + 1] == 0x05 && pTextSection[i + 2] == 0xC3)
                {
                    m_pSyscallGadget = &pTextSection[i];
                    return true;
                }
            }

            return false;
        }

        bool isFunctionHooked(const uint8_t* pFunctionStart) const
        {
            const uint8_t* pCurrent = pFunctionStart;

            while (*pCurrent == 0x90) {
                pCurrent++;
            }

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
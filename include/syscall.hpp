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

#include "shared.hpp"

namespace syscall 
{
    namespace policies 
    {
        struct SectionAllocator 
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/) 
            {
                auto fNtCreateSection = reinterpret_cast<NtCreateSection_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection"));
                auto fNtMapView = reinterpret_cast<NtMapViewOfSection_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection"));
                auto fNtUnmapView = reinterpret_cast<NtUnmapViewOfSection_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
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
            static void release(void* /*pRegion*/, HANDLE /*hHeapHandle*/) 
            {
            }
        };

        struct HeapAllocator 
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& hOutHeapHandle) 
            {
                using HeapCreate_t = HANDLE(WINAPI*)(DWORD, SIZE_T, SIZE_T);
                using HeapAlloc_t = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
                auto fHeapCreate = reinterpret_cast<HeapCreate_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapCreate"));
                auto fHeapAlloc = reinterpret_cast<HeapAlloc_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapAlloc"));

                if (!fHeapCreate || !fHeapAlloc) 
                    return false;

                hOutHeapHandle = fHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
                if (!hOutHeapHandle) 
                    return false;

                pOutRegion = fHeapAlloc(hOutHeapHandle, 0, uRegionSize);
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
                    using HeapDestroy_t = BOOL(WINAPI*)(HANDLE);
                    auto fHeapDestroy = reinterpret_cast<HeapDestroy_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapDestroy"));
                    if (fHeapDestroy)
                        fHeapDestroy(hHeapHandle);
                }
            }
        };

        struct VirtualMemoryAllocator 
        {
            static bool allocate(size_t uRegionSize, const std::vector<uint8_t>& vecBuffer, void*& pOutRegion, HANDLE& /*unused*/) 
            {
                auto fNtAllocate = reinterpret_cast<NtAllocateVirtualMemory_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"));
                auto fNtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"));
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
                if (pRegion) 
                {
                    auto fNtFree = reinterpret_cast<NtFreeVirtualMemory_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory"));
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
            inline static const uint8_t arrShellcode[] = {
               0x51,                               // push rcx
               0x41, 0x5A,                         // pop r10
               0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, 0x00000000 (syscall placeholder)
               0x0F, 0x05,                         // syscall
               0x48, 0x83, 0xC4, 0x08,             // add rsp, 8
               0xFF, 0x64, 0x24, 0xF8              // jmp qword ptr [rsp-8]
            };
            static constexpr size_t getStubSize() { return sizeof(arrShellcode); }
            static void generate(uint8_t* pBuffer, uint32_t uSyscallNumber, void* /*pGadgetAddress*/) 
            {
                memcpy(pBuffer, arrShellcode, sizeof(arrShellcode));
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

            if (!extractSyscalls()) 
                return false;

            m_bInitialized = createSyscalls();
            return m_bInitialized;
        }

        template<typename Ret, typename... Args>
        SYSCALL_FORCE_INLINE  Ret invoke(const std::string& sSyscallName, Args... args) 
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

        bool findSyscallGadget() 
        {
            HMODULE hNtHandle = GetModuleHandleA("ntdll.dll");
            if (!hNtHandle) 
                return false;

            auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hNtHandle);
            auto pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(hNtHandle) + pDosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(pNtHeaders);
            uint8_t* pTextSection = nullptr;
            uint32_t uTextSectionSize = 0;
            for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (strcmp(reinterpret_cast<char*>(sections[i].Name), ".text") == 0)
                {
                    pTextSection = reinterpret_cast<uint8_t*>(hNtHandle) + sections[i].VirtualAddress;
                    uTextSectionSize = sections[i].Misc.VirtualSize;
                    break;
                }
            }

            if (!pTextSection || !uTextSectionSize)
                return false;

            for (DWORD iCurrentByte = 0; iCurrentByte < uTextSectionSize - 2; ++iCurrentByte)
            {
                if (pTextSection[iCurrentByte] == 0x0F && pTextSection[iCurrentByte + 1] == 0x05 && pTextSection[iCurrentByte + 2] == 0xC3)
                {
                    m_pSyscallGadget = &pTextSection[iCurrentByte];
                    return true;
                }
            }

            return false;
        }


        bool extractSyscalls() 
        {
            HMODULE hNtdllHandle = GetModuleHandleA("ntdll.dll");
            if (!hNtdllHandle) 
                return false;

            auto pNtdllBase = reinterpret_cast<uint8_t*>(hNtdllHandle);
            auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pNtdllBase);
            auto pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pNtdllBase + pDosHeader->e_lfanew);
            auto pExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            auto pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pNtdllBase + pExportDirRVA);
            auto pFunctionsRVA = reinterpret_cast<uint32_t*>(pNtdllBase + pExportDir->AddressOfFunctions);
            auto pNamesRVA = reinterpret_cast<uint32_t*>(pNtdllBase + pExportDir->AddressOfNames);
            auto pOrdinalsRva = reinterpret_cast<uint16_t*>(pNtdllBase + pExportDir->AddressOfNameOrdinals);
            for (uint32_t i = 0; i < pExportDir->NumberOfNames; i++) 
            {
                const char* szName = reinterpret_cast<const char*>(pNtdllBase + pNamesRVA[i]);
                if (strncmp(szName, "Nt", 2) != 0)
                    continue;
                    
                uint16_t uOrdinal = pOrdinalsRva[i];
                uint32_t uFunctionRva = pFunctionsRVA[uOrdinal];
                if (uFunctionRva >= pExportDirRVA && uFunctionRva < pExportDirRVA + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
                    continue;

                uint8_t* pFunctionStart = pNtdllBase + uFunctionRva;
                if (*reinterpret_cast<uint32_t*>(pFunctionStart) == 0xB8D18B4C) 
                {
                    std::string sName = szName;
                    uint32_t uSyscallNumber = *reinterpret_cast<uint32_t*>(pFunctionStart + 4);

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
    };
}

using SyscallSectionGadget = syscall::Manager<syscall::policies::SectionAllocator, syscall::policies::GadgetStubGenerator>;
using SyscallHeapGadget = syscall::Manager<syscall::policies::HeapAllocator, syscall::policies::GadgetStubGenerator>;
using SyscallSectionDirect = syscall::Manager<syscall::policies::SectionAllocator, syscall::policies::DirectStubGenerator>;

#endif 
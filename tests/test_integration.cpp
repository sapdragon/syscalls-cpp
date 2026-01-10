#include <gtest/gtest.h>
#include <syscalls-cpp/syscall.hpp>

class SyscallManagerTest : public ::testing::Test {};

TEST_F(SyscallManagerTest, InitializesWithSectionDirect)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::direct
    > manager;

    EXPECT_TRUE(manager.initialize());
}

TEST_F(SyscallManagerTest, InitializesWithHeapDirect)
{
    syscall::Manager<
        syscall::policies::allocator::heap,
        syscall::policies::generator::direct
    > manager;

    EXPECT_TRUE(manager.initialize());
}

TEST_F(SyscallManagerTest, InitializesWithMemoryDirect)
{
    syscall::Manager<
        syscall::policies::allocator::memory,
        syscall::policies::generator::direct
    > manager;

    EXPECT_TRUE(manager.initialize());
}

#if SYSCALL_PLATFORM_WINDOWS_64
TEST_F(SyscallManagerTest, InitializesWithGadgetX64)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::gadget
    > manager;

    EXPECT_TRUE(manager.initialize());
}

TEST_F(SyscallManagerTest, InitializesWithExceptionX64)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::exception
    > manager;

    EXPECT_TRUE(manager.initialize());
}
#endif

TEST_F(SyscallManagerTest, DoubleInitSucceeds)
{
    SyscallSectionDirect manager;
    EXPECT_TRUE(manager.initialize());
    EXPECT_TRUE(manager.initialize());
}

TEST_F(SyscallManagerTest, MoveConstructorWorks)
{
    SyscallSectionDirect manager1;
    ASSERT_TRUE(manager1.initialize());

    SyscallSectionDirect manager2 = std::move(manager1);

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager2.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));

    if (pBaseAddress)
    {
        uRegionSize = 0;
        manager2.invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

class SyscallInvokeTest : public ::testing::Test
{
protected:
    SyscallSectionDirect manager;

    void SetUp() override
    {
        ASSERT_TRUE(manager.initialize());
    }
};

TEST_F(SyscallInvokeTest, NtAllocateVirtualMemory)
{
    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_NE(pBaseAddress, nullptr);
    EXPECT_GE(uRegionSize, 0x1000u);

    if (pBaseAddress)
    {
        uRegionSize = 0;
        manager.invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

TEST_F(SyscallInvokeTest, NtQuerySystemInformation)
{
    ULONG uReturnLength = 0;
    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtQuerySystemInformation"),
        0,
        nullptr,
        0,
        &uReturnLength
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000004));
    EXPECT_GT(uReturnLength, 0u);
}

TEST_F(SyscallInvokeTest, InvalidSyscallReturnsNotFound)
{
    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtThisFunctionDoesNotExist123456")
    );

    EXPECT_EQ(status, syscall::native::STATUS_PROCEDURE_NOT_FOUND);
}

TEST_F(SyscallInvokeTest, NtCloseInvalidHandle)
{
    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtClose"),
        reinterpret_cast<HANDLE>(0xDEADBEEF)
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000008));
}

class NativeApiTest : public ::testing::Test {};

TEST_F(NativeApiTest, GetModuleBaseNtdll)
{
    HMODULE hNtdll = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("ntdll.dll")
    );
    EXPECT_NE(hNtdll, nullptr);
}

TEST_F(NativeApiTest, GetModuleBaseKernel32)
{
    HMODULE hKernel32 = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("kernel32.dll")
    );
    EXPECT_NE(hKernel32, nullptr);
}

TEST_F(NativeApiTest, GetModuleBaseWideString)
{
    HMODULE hNtdll = syscall::native::getModuleBase(L"ntdll.dll");
    EXPECT_NE(hNtdll, nullptr);
}

TEST_F(NativeApiTest, GetModuleBaseInvalidReturnsNull)
{
    HMODULE hInvalid = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("this_dll_does_not_exist.dll")
    );
    EXPECT_EQ(hInvalid, nullptr);
}

TEST_F(NativeApiTest, GetExportAddressNtClose)
{
    HMODULE hNtdll = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("ntdll.dll")
    );
    ASSERT_NE(hNtdll, nullptr);

    void* pNtClose = syscall::native::getExportAddress(hNtdll, SYSCALL_ID("NtClose"));
    EXPECT_NE(pNtClose, nullptr);
}

TEST_F(NativeApiTest, GetExportAddressWithStringName)
{
    HMODULE hNtdll = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("ntdll.dll")
    );
    ASSERT_NE(hNtdll, nullptr);

    void* pNtClose = syscall::native::getExportAddress(hNtdll, "NtClose");
    EXPECT_NE(pNtClose, nullptr);
}

TEST_F(NativeApiTest, GetExportAddressInvalidReturnsNull)
{
    HMODULE hNtdll = syscall::native::getModuleBase(
        syscall::hashing::calculateHash("ntdll.dll")
    );
    ASSERT_NE(hNtdll, nullptr);

    void* pInvalid = syscall::native::getExportAddress(
        hNtdll,
        SYSCALL_ID("ThisExportDoesNotExist123")
    );
    EXPECT_EQ(pInvalid, nullptr);
}

TEST_F(NativeApiTest, GetCurrentPEBNotNull)
{
    auto pPeb = syscall::native::getCurrentPEB();
    EXPECT_NE(pPeb, nullptr);
}

TEST_F(NativeApiTest, RdtscpReturnsValue)
{
    uint64_t uValue1 = syscall::native::rdtscp();
    uint64_t uValue2 = syscall::native::rdtscp();

    EXPECT_NE(uValue1, uValue2);
    EXPECT_NE(uValue1, 0u);
}

TEST(ManagerOwnershipTest, MoveAssignmentWorks)
{
    SyscallSectionDirect manager1;
    ASSERT_TRUE(manager1.initialize());

    SyscallSectionDirect manager2;
    manager2 = std::move(manager1);

    PVOID pAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager2.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));

    if (pAddress)
    {
        uRegionSize = 0;
        manager2.invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

class NativeApiExtendedTest : public ::testing::Test {};

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiBasic)
{
    auto uHash1 = syscall::native::calculateHashRuntimeCi(L"ntdll.dll");
    auto uHash2 = syscall::native::calculateHashRuntimeCi(L"NTDLL.DLL");
    auto uHash3 = syscall::native::calculateHashRuntimeCi(L"NtDlL.DlL");

    EXPECT_EQ(uHash1, uHash2);
    EXPECT_EQ(uHash1, uHash3);
    EXPECT_NE(uHash1, 0u);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiDifferentStrings)
{
    auto uHash1 = syscall::native::calculateHashRuntimeCi(L"ntdll.dll");
    auto uHash2 = syscall::native::calculateHashRuntimeCi(L"kernel32.dll");

    EXPECT_NE(uHash1, uHash2);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiWcharNull)
{
    auto uHash = syscall::native::calculateHashRuntimeCi(static_cast<const wchar_t*>(nullptr));
    EXPECT_EQ(uHash, 0u);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiEmpty)
{
    auto uHash = syscall::native::calculateHashRuntimeCi(L"");
    EXPECT_EQ(uHash, syscall::hashing::polyKey1);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiCharBasic)
{
    auto uHash1 = syscall::native::calculateHashRuntimeCi("ntdll");
    auto uHash2 = syscall::native::calculateHashRuntimeCi("NTDLL");
    auto uHash3 = syscall::native::calculateHashRuntimeCi("NtDlL");

    EXPECT_EQ(uHash1, uHash2);
    EXPECT_EQ(uHash1, uHash3);
    EXPECT_NE(uHash1, 0u);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiCharNull)
{
    auto uHash = syscall::native::calculateHashRuntimeCi(static_cast<const char*>(nullptr));
    EXPECT_EQ(uHash, 0u);
}

TEST_F(NativeApiExtendedTest, CalculateHashRuntimeCiCharMatchesWchar)
{
    auto uHashChar = syscall::native::calculateHashRuntimeCi("kernel32");
    auto uHashWchar = syscall::native::calculateHashRuntimeCi(L"kernel32");

    EXPECT_EQ(uHashChar, uHashWchar);
}

TEST_F(NativeApiExtendedTest, GetModuleBaseNullWideString)
{
    HMODULE hModule = syscall::native::getModuleBase(static_cast<const wchar_t*>(nullptr));
    EXPECT_EQ(hModule, nullptr);
}

TEST_F(NativeApiExtendedTest, GetModuleBaseCaseInsensitive)
{
    HMODULE hNtdll1 = syscall::native::getModuleBase(L"ntdll.dll");
    HMODULE hNtdll2 = syscall::native::getModuleBase(L"NTDLL.DLL");
    HMODULE hNtdll3 = syscall::native::getModuleBase(L"NtDlL.DlL");

    EXPECT_NE(hNtdll1, nullptr);
    EXPECT_EQ(hNtdll1, hNtdll2);
    EXPECT_EQ(hNtdll1, hNtdll3);
}

TEST_F(NativeApiExtendedTest, GetExportAddressNullModule)
{
    void* pAddr = syscall::native::getExportAddress(nullptr, "NtClose");
    EXPECT_EQ(pAddr, nullptr);
}

TEST_F(NativeApiExtendedTest, GetExportAddressNullName)
{
    HMODULE hNtdll = syscall::native::getModuleBase(L"ntdll.dll");
    ASSERT_NE(hNtdll, nullptr);

    void* pAddr = syscall::native::getExportAddress(hNtdll, static_cast<const char*>(nullptr));
    EXPECT_EQ(pAddr, nullptr);
}

TEST_F(NativeApiExtendedTest, GetExportAddressHashNullModule)
{
    void* pAddr = syscall::native::getExportAddress(nullptr, SYSCALL_ID("NtClose"));
    EXPECT_EQ(pAddr, nullptr);
}

TEST_F(NativeApiExtendedTest, GetExportAddressMultipleFunctions)
{
    HMODULE hNtdll = syscall::native::getModuleBase(L"ntdll.dll");
    ASSERT_NE(hNtdll, nullptr);

    void* pNtClose = syscall::native::getExportAddress(hNtdll, "NtClose");
    void* pNtOpenProcess = syscall::native::getExportAddress(hNtdll, "NtOpenProcess");
    void* pNtReadFile = syscall::native::getExportAddress(hNtdll, "NtReadFile");

    EXPECT_NE(pNtClose, nullptr);
    EXPECT_NE(pNtOpenProcess, nullptr);
    EXPECT_NE(pNtReadFile, nullptr);
    EXPECT_NE(pNtClose, pNtOpenProcess);
    EXPECT_NE(pNtClose, pNtReadFile);
}

TEST_F(NativeApiExtendedTest, GetExportAddressForwardedFunction)
{
    HMODULE hKernel32 = syscall::native::getModuleBase(L"kernel32.dll");
    ASSERT_NE(hKernel32, nullptr);

    void* pHeapAlloc = syscall::native::getExportAddress(hKernel32, "HeapAlloc");
    EXPECT_NE(pHeapAlloc, nullptr);
}

TEST_F(NativeApiExtendedTest, GetExportAddressZwFunctions)
{
    HMODULE hNtdll = syscall::native::getModuleBase(L"ntdll.dll");
    ASSERT_NE(hNtdll, nullptr);

    void* pZwClose = syscall::native::getExportAddress(hNtdll, "ZwClose");
    void* pNtClose = syscall::native::getExportAddress(hNtdll, "NtClose");

    EXPECT_NE(pZwClose, nullptr);
    EXPECT_NE(pNtClose, nullptr);
}

TEST_F(NativeApiExtendedTest, GetCurrentPEBFields)
{
    auto pPeb = syscall::native::getCurrentPEB();
    ASSERT_NE(pPeb, nullptr);

    EXPECT_NE(pPeb->Ldr, nullptr);
    EXPECT_NE(pPeb->ProcessParameters, nullptr);
}

TEST_F(NativeApiExtendedTest, RdtscpIncreasing)
{
    uint64_t uValues[10];
    for (int i = 0; i < 10; ++i)
        uValues[i] = syscall::native::rdtscp();

    for (int i = 1; i < 10; ++i)
        EXPECT_GT(uValues[i], uValues[i - 1]);
}

TEST_F(NativeApiExtendedTest, IsSuccessFunction)
{
    EXPECT_TRUE(syscall::native::isSuccess(0));
    EXPECT_TRUE(syscall::native::isSuccess(0x00000001));
    EXPECT_FALSE(syscall::native::isSuccess(static_cast<NTSTATUS>(0xC0000001)));
    EXPECT_FALSE(syscall::native::isSuccess(static_cast<NTSTATUS>(0x80000001)));
}

TEST_F(NativeApiExtendedTest, GetCurrentProcessHandle)
{
    HANDLE hProcess = syscall::native::getCurrentProcess();
    EXPECT_EQ(hProcess, reinterpret_cast<HANDLE>(-1));
}

class SyscallPolicyTest : public ::testing::Test {};

TEST_F(SyscallPolicyTest, SignatureParserDirect)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::direct,
        syscall::policies::parser::signature
    > manager;

    EXPECT_TRUE(manager.initialize());

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));

    if (pBaseAddress)
    {
        uRegionSize = 0;
        manager.invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

TEST_F(SyscallPolicyTest, DirectoryParserDirect)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::direct,
        syscall::policies::parser::directory
    > manager;

    EXPECT_TRUE(manager.initialize());

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtClose"),
        reinterpret_cast<HANDLE>(0xDEADBEEF)
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000008));
}

TEST_F(SyscallPolicyTest, HeapAllocatorWithSignatureParser)
{
    syscall::Manager<
        syscall::policies::allocator::heap,
        syscall::policies::generator::direct,
        syscall::policies::parser::signature
    > manager;

    EXPECT_TRUE(manager.initialize());

    ULONG uReturnLength = 0;
    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtQuerySystemInformation"),
        0,
        nullptr,
        0,
        &uReturnLength
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000004));
}

TEST_F(SyscallPolicyTest, MemoryAllocatorWithSignatureParser)
{
    syscall::Manager<
        syscall::policies::allocator::memory,
        syscall::policies::generator::direct,
        syscall::policies::parser::signature
    > manager;

    EXPECT_TRUE(manager.initialize());

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtClose"),
        reinterpret_cast<HANDLE>(0xDEADBEEF)
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000008));
}

#if SYSCALL_PLATFORM_WINDOWS_64
TEST_F(SyscallPolicyTest, GadgetGeneratorWithSignatureParser)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::gadget,
        syscall::policies::parser::signature
    > manager;

    EXPECT_TRUE(manager.initialize());

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtClose"),
        reinterpret_cast<HANDLE>(0xDEADBEEF)
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000008));
}

TEST_F(SyscallPolicyTest, ExceptionGeneratorWithSignatureParser)
{
    syscall::Manager<
        syscall::policies::allocator::section,
        syscall::policies::generator::exception,
        syscall::policies::parser::signature
    > manager;

    EXPECT_TRUE(manager.initialize());

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtClose"),
        reinterpret_cast<HANDLE>(0xDEADBEEF)
    );

    EXPECT_EQ(status, static_cast<NTSTATUS>(0xC0000008));
}
#endif

TEST_F(SyscallPolicyTest, InvokeWithoutInitialize)
{
    SyscallSectionDirect manager;

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_NE(pBaseAddress, nullptr);

    if (pBaseAddress)
    {
        uRegionSize = 0;
        manager.invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

TEST_F(SyscallPolicyTest, MultipleSyscallsSequentially)
{
    SyscallSectionDirect manager;
    ASSERT_TRUE(manager.initialize());

    for (int i = 0; i < 100; ++i)
    {
        PVOID pBaseAddress = nullptr;
        SIZE_T uRegionSize = 0x1000;

        NTSTATUS status = manager.invoke<NTSTATUS>(
            SYSCALL_ID("NtAllocateVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            0,
            &uRegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        EXPECT_TRUE(NT_SUCCESS(status));

        if (pBaseAddress)
        {
            uRegionSize = 0;
            manager.invoke<NTSTATUS>(
                SYSCALL_ID("NtFreeVirtualMemory"),
                syscall::native::getCurrentProcess(),
                &pBaseAddress,
                &uRegionSize,
                MEM_RELEASE
            );
        }
    }
}

TEST_F(SyscallPolicyTest, NtProtectVirtualMemory)
{
    SyscallSectionDirect manager;
    ASSERT_TRUE(manager.initialize());

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    ASSERT_TRUE(NT_SUCCESS(status));
    ASSERT_NE(pBaseAddress, nullptr);

    ULONG uOldProtect = 0;
    SIZE_T uProtectSize = 0x1000;
    PVOID pProtectAddress = pBaseAddress;

    status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtProtectVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pProtectAddress,
        &uProtectSize,
        PAGE_EXECUTE_READ,
        &uOldProtect
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_EQ(uOldProtect, PAGE_READWRITE);

    uRegionSize = 0;
    manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtFreeVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        &uRegionSize,
        MEM_RELEASE
    );
}

TEST_F(SyscallPolicyTest, NtQueryVirtualMemory)
{
    SyscallSectionDirect manager;
    ASSERT_TRUE(manager.initialize());

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    ASSERT_TRUE(NT_SUCCESS(status));

    MEMORY_BASIC_INFORMATION memInfo{};
    SIZE_T uReturnLength = 0;

    status = manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtQueryVirtualMemory"),
        syscall::native::getCurrentProcess(),
        pBaseAddress,
        0,
        &memInfo,
        sizeof(memInfo),
        &uReturnLength
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_EQ(memInfo.BaseAddress, pBaseAddress);
    EXPECT_EQ(memInfo.Protect, PAGE_READWRITE);
    EXPECT_EQ(memInfo.State, MEM_COMMIT);

    uRegionSize = 0;
    manager.invoke<NTSTATUS>(
        SYSCALL_ID("NtFreeVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        &uRegionSize,
        MEM_RELEASE
    );
}


#include <gtest/gtest.h>
#include <syscalls-cpp/hash.hpp>

using namespace syscall::hashing;

TEST(HashTest, CompileTimeHashNotZero)
{
    constexpr auto uHash = calculateHash("NtAllocateVirtualMemory");
    static_assert(uHash != 0);
    EXPECT_NE(uHash, 0);
}

TEST(HashTest, DifferentStringsDifferentHashes)
{
    constexpr auto uHash1 = calculateHash("NtAllocateVirtualMemory");
    constexpr auto uHash2 = calculateHash("NtFreeVirtualMemory");
    static_assert(uHash1 != uHash2);
    EXPECT_NE(uHash1, uHash2);
}

TEST(HashTest, SameStringSameHash)
{
    constexpr auto uHash1 = calculateHash("ntdll.dll");
    constexpr auto uHash2 = calculateHash("ntdll.dll");
    static_assert(uHash1 == uHash2);
    EXPECT_EQ(uHash1, uHash2);
}

TEST(HashTest, RuntimeMatchesCompileTime)
{
    constexpr auto uCompileTimeHash = calculateHash("NtClose");
    auto uRuntimeHash = calculateHashRuntime("NtClose");
    EXPECT_EQ(uCompileTimeHash, uRuntimeHash);
}

TEST(HashTest, PartialHashWithLength)
{
    constexpr auto uFullHash = calculateHash("Nt");
    constexpr auto uPartialHash = calculateHash("NtAllocateVirtualMemory", 2);
    static_assert(uFullHash == uPartialHash);
    EXPECT_EQ(uFullHash, uPartialHash);
}

TEST(HashTest, RuntimePartialHashWithLength)
{
    auto uFullHash = calculateHashRuntime("Zw");
    auto uPartialHash = calculateHashRuntime("ZwAllocateVirtualMemory", 2);
    EXPECT_EQ(uFullHash, uPartialHash);
}

TEST(HashTest, StringViewWorks)
{
    std::string_view svName = "NtQuerySystemInformation";
    auto uSvHash = calculateHashRuntime(svName);
    auto uPtrHash = calculateHashRuntime("NtQuerySystemInformation");
    EXPECT_EQ(uSvHash, uPtrHash);
}

TEST(HashTest, StringViewPartial)
{
    std::string_view svName = "NtClose";
    std::string_view svPartial = svName.substr(0, 2);
    auto uPartialHash = calculateHashRuntime(svPartial);
    auto uExpectedHash = calculateHashRuntime("Nt");
    EXPECT_EQ(uPartialHash, uExpectedHash);
}

TEST(HashTest, EmptyString)
{
    auto uHash = calculateHashRuntime("");
    EXPECT_EQ(uHash, polyKey1);
}

TEST(HashTest, SeedIsConsistent)
{
    EXPECT_EQ(currentSeed, getCompileTimeSeed());
}

TEST(HashTest, CommonNtFunctionsUnique)
{
    constexpr auto uHash1 = calculateHash("NtClose");
    constexpr auto uHash2 = calculateHash("NtOpenProcess");
    constexpr auto uHash3 = calculateHash("NtReadFile");
    constexpr auto uHash4 = calculateHash("NtWriteFile");
    constexpr auto uHash5 = calculateHash("NtCreateFile");

    EXPECT_NE(uHash1, uHash2);
    EXPECT_NE(uHash1, uHash3);
    EXPECT_NE(uHash1, uHash4);
    EXPECT_NE(uHash1, uHash5);
    EXPECT_NE(uHash2, uHash3);
    EXPECT_NE(uHash2, uHash4);
    EXPECT_NE(uHash2, uHash5);
    EXPECT_NE(uHash3, uHash4);
    EXPECT_NE(uHash3, uHash5);
    EXPECT_NE(uHash4, uHash5);
}

TEST(HashTest, DllNamesUnique)
{
    constexpr auto uHash1 = calculateHash("ntdll.dll");
    constexpr auto uHash2 = calculateHash("kernel32.dll");
    constexpr auto uHash3 = calculateHash("user32.dll");

    EXPECT_NE(uHash1, uHash2);
    EXPECT_NE(uHash1, uHash3);
    EXPECT_NE(uHash2, uHash3);
}

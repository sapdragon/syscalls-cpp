#include <gtest/gtest.h>
#include <syscalls-cpp/crt.hpp>
#include <cstring>

using namespace syscall::crt;

TEST(CrtTest, GetCountOfReturnsCorrectSize)
{
    int arrInt[10];
    EXPECT_EQ(getCountOf(arrInt), 10);

    char arrChar[256];
    EXPECT_EQ(getCountOf(arrChar), 256);
}

TEST(CrtTest, ConcatBasic)
{
    wchar_t wzDest[32] = L"Hello";
    string::concat(wzDest, 32, L" World");
    EXPECT_STREQ(wzDest, L"Hello World");
}

TEST(CrtTest, ConcatEmptySource)
{
    wchar_t wzDest[32] = L"Hello";
    string::concat(wzDest, 32, L"");
    EXPECT_STREQ(wzDest, L"Hello");
}

TEST(CrtTest, ConcatEmptyDest)
{
    wchar_t wzDest[32] = L"";
    string::concat(wzDest, 32, L"World");
    EXPECT_STREQ(wzDest, L"World");
}

TEST(CrtTest, ConcatTruncatesWhenFull)
{
    wchar_t wzDest[10] = L"Hello";
    string::concat(wzDest, 10, L"WorldWorldWorld");
    EXPECT_LT(string::getLength(wzDest), 10u);
}

TEST(CrtTest, ConcatNullDest)
{
    string::concat(nullptr, 32, L"test");
}

TEST(CrtTest, ConcatZeroSize)
{
    wchar_t wzDest[32] = L"Hello";
    string::concat(wzDest, 0, L" World");
    EXPECT_STREQ(wzDest, L"Hello");
}

TEST(CrtTest, MbToWcsBasic)
{
    wchar_t wzDest[32];
    string::mbToWcs(wzDest, 32, "hello");
    EXPECT_STREQ(wzDest, L"hello");
}

TEST(CrtTest, MbToWcsEmpty)
{
    wchar_t wzDest[32] = L"garbage";
    string::mbToWcs(wzDest, 32, "");
    EXPECT_STREQ(wzDest, L"");
}

TEST(CrtTest, MbToWcsTruncates)
{
    wchar_t wzDest[5];
    string::mbToWcs(wzDest, 5, "hello world");
    EXPECT_EQ(string::getLength(wzDest), 4u);
    EXPECT_EQ(wzDest[4], L'\0');
}

TEST(CrtTest, MbToWcsNullDest)
{
    string::mbToWcs(nullptr, 32, "test");
}

TEST(CrtTest, MbToWcsZeroSize)
{
    wchar_t wzDest[32] = L"garbage";
    string::mbToWcs(wzDest, 0, "test");
    EXPECT_STREQ(wzDest, L"garbage");
}

TEST(CrtTest, GetLengthIsConstexpr)
{
    constexpr size_t uLen = string::getLength("compile time");
    static_assert(uLen == 12);
    EXPECT_EQ(uLen, 12u);
}

TEST(CrtTest, ToLowerIsConstexpr)
{
    constexpr char cLower = string::toLower('X');
    static_assert(cLower == 'x');
    EXPECT_EQ(cLower, 'x');
}

TEST(CrtTest, GetCountOfIsConstexpr)
{
    constexpr int arrTest[42] = {};
    constexpr size_t uCount = getCountOf(arrTest);
    static_assert(uCount == 42);
    EXPECT_EQ(uCount, 42u);
}

TEST(CrtTest, CompareIgnoreCaseEqual)
{
    EXPECT_EQ(string::compareIgnoreCase(L"ntdll.dll", L"NTDLL.DLL"), 0);
    EXPECT_EQ(string::compareIgnoreCase(L"Kernel32.dll", L"kernel32.dll"), 0);
    EXPECT_EQ(string::compareIgnoreCase(L"", L""), 0);
}

TEST(CrtTest, CompareIgnoreCaseDifferent)
{
    EXPECT_NE(string::compareIgnoreCase(L"ntdll.dll", L"kernel32.dll"), 0);
    EXPECT_NE(string::compareIgnoreCase(L"abc", L"abd"), 0);
}

TEST(CrtTest, CompareIgnoreCaseOrdering)
{
    EXPECT_LT(string::compareIgnoreCase(L"abc", L"abd"), 0);
    EXPECT_GT(string::compareIgnoreCase(L"abd", L"abc"), 0);
    EXPECT_LT(string::compareIgnoreCase(L"ABC", L"ABD"), 0);
}

TEST(CrtTest, CompareIgnoreCaseLengthDifference)
{
    EXPECT_LT(string::compareIgnoreCase(L"abc", L"abcd"), 0);
    EXPECT_GT(string::compareIgnoreCase(L"abcd", L"abc"), 0);
}

TEST(CrtTest, CompareIgnoreCaseIsConstexpr)
{
    constexpr int nResult = string::compareIgnoreCase(L"Test", L"TEST");
    static_assert(nResult == 0);
    EXPECT_EQ(nResult, 0);
}

TEST(CrtTest, ToLowerWcharIsConstexpr)
{
    constexpr wchar_t wcLower = string::toLower(L'X');
    static_assert(wcLower == L'x');
    EXPECT_EQ(wcLower, L'x');
}
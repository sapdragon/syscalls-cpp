#ifndef SYSCALL_CRT_HPP
#define SYSCALL_CRT_HPP

#include <cstdint>
#include <cwchar>

namespace syscall::crt
{
    template<typename T, size_t N>
    [[nodiscard]] constexpr size_t getCountOf(T(&)[N]) noexcept
    {
        return N;
    }

    namespace memory
    {
        inline void* copy(void* pDest, const void* pSource, size_t uCount) noexcept
        {
            auto* d = static_cast<unsigned char*>(pDest);
            const auto* s = static_cast<const unsigned char*>(pSource);
            for (size_t i = 0; i < uCount; ++i)
                d[i] = s[i];

            return pDest;
        }

        inline void* set(void* pDest, int iValue, size_t uCount) noexcept
        {
            auto* d = static_cast<unsigned char*>(pDest);
            const unsigned char ucByteValue = static_cast<unsigned char>(iValue);
            for (size_t i = 0; i < uCount; ++i)
                d[i] = ucByteValue;

            return pDest;
        }

        inline int compare(const void* pBuffer1, const void* pBuffer2, size_t uCount) noexcept
        {
            const auto* s1 = static_cast<const unsigned char*>(pBuffer1);
            const auto* s2 = static_cast<const unsigned char*>(pBuffer2);

            for (size_t i = 0; i < uCount; ++i)
            {
                if (s1[i] != s2[i])
                    return s1[i] - s2[i];
            }

            return 0;
        }
    }

    namespace string
    {
        constexpr char toLower(char c) noexcept 
        {
            return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c; 
        }
        constexpr wchar_t toLower(wchar_t c) noexcept 
        { 
            return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c; 
        }

        constexpr size_t getLength(const char* szStr) noexcept
        {
            const char* s = szStr;
            while (*s) 
                ++s;

            return s - szStr;
        }

        constexpr size_t getLength(const wchar_t* wzStr) noexcept
        {
            const wchar_t* s = wzStr;
            while (*s) 
                ++s;

            return s - wzStr;
        }

        [[nodiscard]] constexpr int compare(const char* szFirst, const char* szSecond) noexcept
        {
            while (*szFirst && (*szFirst == *szSecond)) 
            {
                szFirst++; 
                szSecond++; 
            }

            return *(const unsigned char*)szFirst - *(const unsigned char*)szSecond;
        }

        [[nodiscard]] constexpr int compareIgnoreCase(const wchar_t* szFirst, const wchar_t* szSecond) noexcept
        {
            wchar_t c1, c2;
            do {
                c1 = toLower(*szFirst++);
                c2 = toLower(*szSecond++);

                if (c1 == L'\0') 
                    return c1 - c2;
            } while (c1 == c2);

            return c1 - c2;
        }

        [[nodiscard]] constexpr const char* findChar(const char* str, int character) noexcept
        {
            while (*str != '\0') 
            {
                if (*str == static_cast<char>(character)) 
                    return str;

                str++;
            }
            return nullptr;
        }

        [[nodiscard]] inline char* findChar(char* str, int character) noexcept
        {
            return const_cast<char*>(findChar(static_cast<const char*>(str), character));
        }

        inline void copy(char* szDest, size_t uDestLength, const char* src) noexcept
        {
            if (!szDest || !uDestLength)
                return;

            const size_t uSourceLength = getLength(src);

            const size_t uCount = (uSourceLength < uDestLength) ? uSourceLength : (uDestLength - 1);
            memory::copy(szDest, src, uCount);
            szDest[uCount] = '\0';
        }

        inline void concat(wchar_t* pDest, size_t uSizeInElements, const wchar_t* pSource) noexcept
        {
            if (!pDest || uSizeInElements == 0)
                return;

            const size_t uDestLength = getLength(pDest);
            if (uDestLength >= uSizeInElements - 1)
                return;


            const size_t uSourceLength = getLength(pSource);
            const size_t uRemainingSpace = uSizeInElements - uDestLength - 1;
            const size_t uCount = (uSourceLength < uRemainingSpace) ? uSourceLength : uRemainingSpace;

            memory::copy(pDest + uDestLength, pSource, uCount * sizeof(wchar_t));
            pDest[uDestLength + uCount] = L'\0';
        }

        inline void mbToWcs(wchar_t* pDest, size_t uSizeInElements, const char* pSource) noexcept
        {
            if (!pDest || uSizeInElements)
                return;

            const size_t uSourceLength = getLength(pSource);
            const size_t uCount = (uSourceLength < uSizeInElements) ? uSourceLength : (uSizeInElements - 1);
            for (size_t i = 0; i < uCount; ++i)
                pDest[i] = static_cast<wchar_t>(static_cast<unsigned char>(pSource[i]));

            pDest[uCount] = L'\0';
        }
    }
}

#endif
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

    namespace string
    {
        [[nodiscard]] constexpr char toLower(char c) noexcept
        {
            return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
        }
        
        [[nodiscard]] constexpr wchar_t toLower(wchar_t c) noexcept
        {
            return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
        }
        
        [[nodiscard]] constexpr size_t getLength(const char* szStr) noexcept
        {
            const char* s = szStr;
            while (*s) 
                ++s;

            return s - szStr;
        }
        
        [[nodiscard]] constexpr size_t getLength(const wchar_t* wzStr) noexcept
        {
            const wchar_t* s = wzStr;
            while (*s) 
                ++s;

            return s - wzStr;
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

        inline void concat(wchar_t* pDest, size_t uSizeInElements, const wchar_t* pSource) noexcept
        {
            if (!pDest || !uSizeInElements)
                return;

            const size_t uDestLength = getLength(pDest);
            if (uDestLength >= uSizeInElements - 1)
                return;


            const size_t uSourceLength = getLength(pSource);
            const size_t uRemainingSpace = uSizeInElements - uDestLength - 1;
            const size_t uCount = (uSourceLength < uRemainingSpace) ? uSourceLength : uRemainingSpace;

            std::copy_n(pSource, uCount * sizeof(wchar_t), pDest + uDestLength);
            pDest[uDestLength + uCount] = L'\0';
        }

        inline void mbToWcs(wchar_t* pDest, size_t uSizeInElements, const char* pSource) noexcept
        {
            if (!pDest || !uSizeInElements)
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

#ifndef HASHING_HPP
#define HASHING_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <bit>

namespace syscall::hashing
{
    using Hash_t = uint64_t;

    constexpr Hash_t getCompileTimeSeed()
    {
        Hash_t seed = 0;
        const char* szCurrentTime = __TIME__;
        const char* szCurrentDate = __DATE__;

        for (int i = 0; szCurrentTime[i] != '\0'; ++i) 
            seed = std::rotr(seed, 3) + szCurrentTime[i];

        for (int i = 0; szCurrentDate[i] != '\0'; ++i) 
            seed = std::rotr(seed, 5) + szCurrentDate[i];

        return seed;
    }

    constexpr Hash_t currentSeed = getCompileTimeSeed();
    constexpr Hash_t polyKey1 = 0xAF6F01BD5B2D7583ULL ^ currentSeed;
    constexpr Hash_t polyKey2 = 0xB4F281729182741DULL ^ std::rotr(currentSeed, 7);

    consteval Hash_t calculateHash(const char* szData)
    {
        Hash_t hash = polyKey1;
        while (*szData)
        {
            hash ^= static_cast<Hash_t>(*szData++);
            hash += std::rotr(hash, 11) + polyKey2;
        }
        return hash;
    }

    consteval Hash_t calculateHash(const char* szData, size_t uLength)
    {
        Hash_t hash = polyKey1;
        for (size_t i = 0; i < uLength && szData[i]; ++i)
        {
            hash ^= static_cast<Hash_t>(szData[i]);
            hash += std::rotr(hash, 11) + polyKey2;
        }
        return hash;
    }


    inline Hash_t calculateHashRuntime(const char* szData)
    {
        Hash_t hash = polyKey1;
        while (*szData)
        {
            hash ^= static_cast<Hash_t>(*szData++);
            hash += std::rotr(hash, 11) + polyKey2;
        }
        return hash;
    }

    inline Hash_t calculateHashRuntime(const char* szData, size_t uLength)
    {
        Hash_t hash = polyKey1;
        for (size_t i = 0; i < uLength && szData[i]; ++i)
        {
            hash ^= static_cast<Hash_t>(szData[i]);
            hash += std::rotr(hash, 11) + polyKey2;
        }
        return hash;
    }

    inline Hash_t calculateHashRuntime(std::string_view sv)
    {
        Hash_t hash = polyKey1;
        for (char c : sv)
        {
            hash ^= static_cast<Hash_t>(c);
            hash += std::rotr(hash, 11) + polyKey2;
        }
        return hash;
    }
}

#ifdef SYSCALLS_NO_HASH
#define SYSCALL_ID(str) (str)
#define SYSCALL_ID_RT(str) (str)
#else
#define SYSCALL_ID(str) (syscall::hashing::calculateHash(str))
#define SYSCALL_ID_RT(str) (syscall::hashing::calculateHashRuntime(str))

#endif

#endif
#ifndef __HASH_COUNT_HPP__
#define __HASH_COUNT_HPP__

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace hibp
{
    typedef std::array<std::uint8_t, 20> sha1_t;

    struct hash_count
    {
        sha1_t data;
        std::uint32_t count{0};
    };

    typedef std::vector<hash_count> collection_t;
    typedef std::array<char, 5> hash_prefix_t;

    std::ostream &operator<<(std::ostream &, sha1_t const &);
    std::ostream &operator<<(std::ostream &, hash_prefix_t const &);

    struct smallest_hash_first
    {
        bool operator()(const hash_count &lhs, const hash_count &rhs)
        {
            return std::lexicographical_compare(lhs.data.begin(), lhs.data.end(), rhs.data.begin(), rhs.data.end());
        }
    };

}

#endif // __HASH_COUNT_HPP__

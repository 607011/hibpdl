/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#include <iomanip>

#if defined(__unix__)
#include <arpa/inet.h>
#endif

#include "hash_count.hpp"

namespace hibp
{

    std::ostream &operator<<(std::ostream &os, sha1_t const &hp)
    {
        for (sha1_t::value_type const c : hp)
        {
            os << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(c);
        }
        return os;
    }

    std::ostream &operator<<(std::ostream &os, hash_prefix_t const &hp)
    {
        for (hash_prefix_t::value_type const c : hp)
        {
            os << c;
        }
        return os;
    }

    void hash_count::dump(std::ostream &os) const
    {
        os.write(reinterpret_cast<char const *>(data.data()), data.size());
        uint32_t const cn = htonl(count);
        os.write(reinterpret_cast<char const *>(&cn), sizeof(cn));
    }

    hash_count &hash_count::read(std::istream &is)
    {
        is.read(reinterpret_cast<char*>(data.data()), data.size());
        uint32_t cn = 0;
        is.read(reinterpret_cast<char*>(&cn), sizeof(cn));
        count = ntohl(cn);
        return *this;
    }
}

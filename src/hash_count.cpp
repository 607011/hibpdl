#include <iomanip>
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

}

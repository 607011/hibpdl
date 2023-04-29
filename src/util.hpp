/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */
#ifndef __UTIL_CPP__
#define __UTIL_CPP__

#include <cstdlib>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace util
{
    char nibble2hex(std::uint8_t nibble);
    uint8_t hex2nibble(char);
    std::vector<std::string> split(const std::string &str, char delim);
    std::pair<std::string, std::string> unpair(const std::string &str, char delim);

    template <typename InputIteratorT, typename SeparatorT>
    std::string join(InputIteratorT input, SeparatorT separator)
    {
        std::ostringstream result;
        auto i = std::begin(input);
        if (i != std::end(input))
        {
            result << *i++;
        }
        while (i != std::end(input))
        {
            result << separator << *i++;
        }
        return result.str();
    }
}

#endif // __UTIL_CPP__

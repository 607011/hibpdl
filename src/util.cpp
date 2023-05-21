/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#include <cassert>
#include <utility>

#include "util.hpp"

namespace util
{

    char nibble2hex(std::uint8_t nibble)
    {
        assert(nibble >= 0 && nibble <= 0xf);
        return (nibble < 10)
                   ? '0' + static_cast<char>(nibble)
                   : 'A' + static_cast<char>(nibble) - 10;
    }

    uint8_t hex2nibble(char c)
    {
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        if ((c >= '0' && c <= '9'))
        {
            return static_cast<uint8_t>(c - '0');
        }
        else if ((c >= 'a' && c <= 'f'))
        {
            return static_cast<uint8_t>(c - 'a' + 10);
        } 
        else if ((c >= 'A' && c <= 'F'))
        {
            return static_cast<uint8_t>(c - 'A' + 10);
        }
        return 0;
    }

    std::vector<std::string> split(const std::string &str, char delim)
    {
        std::vector<std::string> strings;
        size_t start;
        size_t end = 0;
        while ((start = str.find_first_not_of(delim, end)) != std::string::npos)
        {
            end = str.find(delim, start);
            strings.push_back(str.substr(start, end - start));
        }
        return strings;
    }

    std::pair<std::string, std::string> unpair(const std::string &str, char delim)
    {
        std::pair<std::string, std::string> pair;
        auto index = str.find(delim);
        if (index != std::string::npos)
        {
            pair = std::make_pair(str.substr(0, index),
                                  str.substr(index + 1, std::string::npos));
        }
        else
        {
            pair = std::make_pair(str, std::string());
        }
        return pair;
    }

}

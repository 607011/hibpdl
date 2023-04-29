/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#include <algorithm>
#include <cassert>
#include <sstream>
#include <queue>
#include <iostream>
#include <iomanip>

#include "response_parser.hpp"
#include "hibpdl.hpp"
#include "util.hpp"

namespace hibp
{
    const std::string downloader::DefaultUserAgent = std::string(PROJECT_NAME) + "/" + PROJECT_VERSION;
    const std::string downloader::ApiUrl = "https://api.pwnedpasswords.com";

    downloader::downloader(std::size_t max_hash_count)
    {
        collection_.reserve(max_hash_count);
        constexpr std::size_t max_hash = 1 << (4 * 4); // 4 nibbles
        for (std::size_t i = 0; i < max_hash; ++i)
        {
            hash_prefix_t p{
                ::util::nibble2hex(static_cast<std::uint8_t>(i >> 12) & 0xf),
                ::util::nibble2hex(static_cast<std::uint8_t>(i >> 8) & 0xf),
                ::util::nibble2hex(static_cast<std::uint8_t>(i >> 4) & 0xf),
                ::util::nibble2hex(static_cast<std::uint8_t>(i) & 0xf),
                0};
            hash_queue_.emplace(p);
        }
    };

    void downloader::log(std::string const &message)
    {
        const std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << message << std::endl;
    }

    void downloader::error(std::string const &message)
    {
        const std::lock_guard<std::mutex> lock(output_mutex_);
        std::cerr << message << std::endl;
    }

    void downloader::http_worker()
    {
        httplib::Client cli(ApiUrl);
        cli.set_compress(true);

        while (!do_quit_)
        {
            hash_prefix_t prefix;
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if (hash_queue_.empty())
                {
                    return;
                }
                else
                {
                    prefix = hash_queue_.front();
                    hash_queue_.pop();
                }
            }
            collection_t hashes;
            std::size_t nibble = 0x0;
            while (nibble <= 0xf)
            {
                prefix[4] = ::util::nibble2hex(nibble);
                std::string const hash_prefix(prefix.begin(), prefix.end());
                std::string const path = "/range/" + hash_prefix;
                if (httplib::Result res = cli.Get(path.c_str()))
                {
                    std::stringstream ss;
                    if (res->status == 200)
                    {
                        response_parser parser(prefix);
                        collection_t const &result = parser.parse(res->body);
                        auto const &h = result.front();
                        ss << h.data << ':' << std::dec << h.count;
                        hashes.insert(hashes.end(), result.begin(), result.end());
                        ++nibble;
                        log(ss.str());
                    }
                    else
                    {
                        error(ss.str());
                    }
                }
            }
            std::stringstream ss;
            {
                std::lock_guard<std::mutex> lock(collection_mutex_);
                collection_.insert(collection_.end(), hashes.begin(), hashes.end());
                ss << "\u001b[32;1mHashes collected: " << collection_.size() << "\u001b[0m";
            }
            log(ss.str());
        }
    }
}

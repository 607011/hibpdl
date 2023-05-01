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
    namespace
    {
        std::string get_os_name()
        {
#if defined(_MSC_VER)
            return "Windows";
#elif defined(__APPLE__) || defined(__MACH__)
            return "macOS";
#elif defined(__linux__)
            return "Linux";
#elif defined(__FreeBSD__)
            return "FreeBSD";
#elif defined(__unix) || defined(__unix__)
            return "Unix";
#else
            return "Unknown";
#endif
        }
    }
    const std::string downloader::DefaultUserAgent =
        std::string(PROJECT_NAME) + "/" + PROJECT_VERSION + " (" + get_os_name() + ") cpp-httplib";
    const std::string downloader::ApiUrl = "https://api.pwnedpasswords.com";
    constexpr std::size_t MaxHashesInDownload = 2'000;

    downloader::downloader(
        std::size_t first_prefix,
        std::size_t last_prefix,
        std::size_t max_hash_count)
    {
        collection_.reserve(max_hash_count);
        for (std::size_t i = first_prefix; i < last_prefix; ++i)
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

    void downloader::warning(std::string const &message)
    {
        const std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << message << std::endl;
    }

    void downloader::error(std::string const &message)
    {
        const std::lock_guard<std::mutex> lock(output_mutex_);
        std::cerr << message << std::endl;
    }

    void downloader::stop()
    {
        do_quit_.store(true);
    }

    void downloader::http_worker()
    {
        httplib::Client cli(ApiUrl);
        cli.set_compress(true);
        httplib::Headers headers{
            {"User-Agent", DefaultUserAgent}};
        cli.set_default_headers(headers);

        while (!do_quit_.load())
        {
            hash_prefix_t prefix;
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if (hash_queue_.empty())
                {
                    if (verbosity_ > 2)
                    {
                        std::ostringstream os;
                        os << "Queue is empty; thread ID "
                           << std::this_thread::get_id()
                           << " ..." << std::endl;
                        log(os.str());
                    }
                    return;
                }
                else
                {
                    prefix = hash_queue_.front();
                    hash_queue_.pop();
                }
            }
            collection_t hashes;
            hashes.reserve(MaxHashesInDownload);
            std::size_t nibble = 0x0;
            while (nibble <= 0xf)
            {
                if (do_quit_.load())
                {
                    if (verbosity_ > 1)
                    {
                        std::ostringstream ss;
                        ss << "Thread "
                           << std::this_thread::get_id()
                           << " quitting ...";
                        log(ss.str());
                    }
                    return;
                }
                prefix[4] = ::util::nibble2hex(static_cast<std::uint8_t>(nibble));
                std::string const hash_prefix(prefix.begin(), prefix.end());
                std::string const path = "/range/" + hash_prefix;
                if (httplib::Result res = cli.Get(path.c_str()))
                {
                    std::ostringstream ss;
                    if (res->status == 200)
                    {
                        response_parser parser(prefix);
                        collection_t const &result = parser.parse(res->body);
                        auto const &h = result.front();
                        ss << h.data << ':' << std::dec << h.count;
                        hashes.insert(hashes.end(), result.begin(), result.end());
                        ++nibble;
                        if (verbosity_ > 0)
                        {
                            log(ss.str());
                        }
                    }
                    else
                    {
                        ss << "\u001b[31;WARNING: HTTP status code = "
                           << res->status
                           << "\u001b[0m";
                        error(ss.str());
                    }
                }
            }
            std::ostringstream ss;
            {
                std::lock_guard<std::mutex> lock(collection_mutex_);
                collection_.insert(collection_.end(), hashes.begin(), hashes.end());
                if (verbosity_ > 0)
                {
                    ss << "\u001b[32;1mTotal hashes collected: "
                       << collection_.size()
                       << "\u001b[0m";
                    log(ss.str());
                }
            }
        }
        if (verbosity_ > 2)
        {
            std::ostringstream os;
            os << "http_worker() with thread ID "
               << std::this_thread::get_id()
               << " ..." << std::endl;
            log(os.str());
        }
    }
}

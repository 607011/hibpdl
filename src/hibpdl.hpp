/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#ifndef __HIBPDL_HPP__
#define __HIBPDL_HPP__

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <queue>
#include <unordered_map>
#include <vector>

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <httplib.h>

#include "hash_count.hpp"
#include "response_parser.hpp"
#include "util.hpp"

namespace hibp
{
    class downloader final
    {
    public:
        downloader(std::size_t first_prefix, std::size_t last_prefix, std::size_t max_hash_count = 1'000'000);
        downloader(downloader const &) = delete;
        downloader(downloader &&) = delete;

        void http_worker();

        inline void set_quiet(bool quiet)
        {
            quiet_ = quiet;
        }

        inline void set_verbosity(int verbosity)
        {
            verbosity_ = verbosity;
        }

        inline std::size_t queue_size() const
        {
            return hash_queue_.size();
        }

        inline collection_t const &collection() const
        {
            return collection_;
        }

        collection_t const &finalize()
        {
            std::sort(collection_.begin(), collection_.end(), smallest_hash_first());
            return collection_;
        }

        void stop();

        static const std::string ApiUrl;
        static const std::string DefaultUserAgent;

    private:
        std::queue<hash_prefix_t> hash_queue_;
        collection_t collection_;
        std::mutex queue_mutex_;
        std::mutex output_mutex_;
        std::mutex collection_mutex_;
        std::atomic_bool do_quit_ = ATOMIC_VAR_INIT(false);
        int verbosity_{0};
        bool quiet_{false};

        void log(std::string const &message);
        void warning(std::string const &message);
        void error(std::string const &message);
    };

}

#endif // __HIBPDL_HPP__

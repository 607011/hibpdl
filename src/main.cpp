/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <iterator>
#include <mutex>
#include <numeric>
#include <thread>
#include <string>
#include <vector>

#include "timer.hpp"
#include "util.hpp"
#include "hibpdl.hpp"

#ifdef WIN32
#include <Windows.h>
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#endif

namespace chrono = std::chrono;

#ifndef PROJECT_NAME
#define PROJECT_NAME "hibpdl++"
#endif
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "unknown"
#endif

namespace
{
    constexpr size_t DefaultNumThreads = 40U;
    const std::string DefaultOutputFilename = "hash+count.bin";

    void about()
    {
        std::cout
            << PROJECT_NAME << "++ " << PROJECT_VERSION
            << " - Fast, multithreaded downloader for \"';--have i been pwned?\" hashes.\n"
            << "Copyright (c) 2023 Oliver Lau\n";
    }

    void license()
    {
        std::cout
            << "Permission is hereby granted, free of charge, to any person obtaining\n"
               "a copy of this software and associated documentation files (the \"Soft-\n"
               "ware\"), to deal in the Software without restriction, including without\n"
               "limitation the rights to use, copy, modify, merge, publish, distribute,\n"
               "sublicense, and/or sell copies of the Software, and to permit persons\n"
               "to whom the Software is furnished to do so, subject to the following\n"
               "conditions:\n\n"
               "The above copyright notice and this permission notice shall be included\n"
               "in all copies or substantial portions of the Software.\n\n"
               "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
               "EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
               "MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n"
               "IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY\n"
               "CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,\n"
               "TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFT-\n"
               "WARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n";
    }

    void brief_usage()
    {
        std::cout
            << "USAGE: " << PROJECT_NAME << " [options] base_url\n"
            << "\n"
            << "See `" << PROJECT_NAME << " --help` for options\n";
    }

    void usage()
    {
        std::cout
            << "\n"
               "USAGE: "
            << PROJECT_NAME
            << " [options]\n"
               "\n"
               "OPTIONS:\n"
               "\n"
               "  -o FILENAME [--output ...]\n"
               "    Write result to FILENAME.\n"
               "    Default: "
            << DefaultOutputFilename
            << "\n\n"
               "  -v [--verbose]\n"
               "    Increase verbosity of output.\n"
               "\n"
               "  -t N [--threads N]\n"
               "    Run in N threads (default: "
            << DefaultNumThreads << ")"
            << "\n"
               "\n"
               "  --help\n"
               "    Display this help\n"
               "\n"
               "  --license\n"
               "    Display license\n"
               "\n";
    }
}

int main(int argc, char *argv[])
{
    std::size_t num_threads{DefaultNumThreads};
    std::string output_filename(DefaultOutputFilename);
    hibp::downloader hibpdl(900'000'000);
    int verbosity = 0;

    while (true)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"output", required_argument, 0, 'o'},
            {"verbose", no_argument, 0, 'v'},
            {"threads", required_argument, 0, 't'},
            {"help", no_argument, 0, '?'},
            {"license", no_argument, 0, 0},
            {0, 0, 0, 0}};
        int c = getopt_long(argc, argv, "?d:t:v", long_options, &option_index);
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 0:
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 't':
            num_threads = static_cast<unsigned int>(atoi(optarg));
            break;
        case 'v':
            ++verbosity;
            break;
        case '?':
            about();
            usage();
            return EXIT_SUCCESS;
        default:
            break;
        }
    }
    num_threads = std::min(num_threads, hibpdl.queue_size());
    if (verbosity > 0)
    {
        std::cout << "Starting " << num_threads << " worker threads ..." << std::endl;
    }
    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    timer t;
    for (std::size_t i = 0; i < num_threads; ++i)
    {
        workers.emplace_back(&hibp::downloader::http_worker, &hibpdl);
    }
    for (auto &worker : workers)
    {
        worker.join();
    }
    if (verbosity > 0)
    {
        std::cout << "Total time: "
                  << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                  << std::endl;
        std::cout << "Sorting " << hibpdl.collection().size() << " entries ..." << std::endl;
    }
    hibp::collection_t const &collection = hibpdl.finalize();
    if (verbosity > 0)
    {
        std::cout << "Total time: "
                  << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                  << std::endl;
        std::cout << "Writing " << hibpdl.collection().size() << " entries ..." << std::endl;
    }
    std::ofstream out(output_filename, std::ios::binary | std::ios::trunc);
    for (auto const &item : collection)
    {
        out.write(reinterpret_cast<char const*>(item.data.data()), item.data.size());
        uint32_t const count = htonl(item.count);
        out.write(reinterpret_cast<char const*>(&count), sizeof(count));
    }
    if (verbosity > 0)
    {
        std::cout << "Total time: "
                  << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                  << std::endl;
    }
    return EXIT_SUCCESS;
}

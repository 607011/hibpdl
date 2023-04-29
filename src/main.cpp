/*
 * HIBPDL++ - Fast, multithreaded downloader for HaveIBeenPwned hashes
 * Copyright (c) 2023 Oliver Lau <oliver.lau@gmail.com>
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <numeric>
#include <thread>
#include <string>
#include <vector>

#include "timer.hpp"
#include "util.hpp"
#include "hibpdl.hpp"

#if _MSC_VER
#include <Windows.h>
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <signal.h>
#include <unistd.h>
#endif

namespace chrono = std::chrono;
namespace fs = std::filesystem;

#ifndef PROJECT_NAME
#define PROJECT_NAME "hibpdl++"
#endif
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "unknown"
#endif

namespace
{
    constexpr size_t DefaultNumThreads = 4U;
    const std::string DefaultOutputFilename = "hash+count.bin";
    const std::string DefaultCheckpointFilename = "checkpoint";
    const std::string DefaultLockFilename = "lock";
    constexpr std::uint32_t DefaultHashPrefixStep = 0x0040;

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

    fs::path get_home_directory()
    {
#if _MSC_VER
        std::ostringstream os;
        os << getenv("HOMEDRIVE") << getenv("HOMEPATH");
        return fs::path(os.str());
#else
        return fs::path(getenv("HOME"));
#endif
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
            << std::dec << DefaultNumThreads << ")"
            << "\n"
               "\n"
               "  -p PREFIX [--first-prefix]\n"
               "    Begin reading a prefix PREFIX.\n"
               "    PREFIX must be a hexadecimal number.\n"
               "\n"
               "  -s STEP [--prefix-step]\n"
               "    Read data in chunks of STEP prefix steps.\n"
               "    STEP must be a hexadecimal number.\n"
               "    Default: "
            << std::hex << std::setw(4) << std::setfill('0') << DefaultHashPrefixStep
            << "\n"
               "  -y\n"
               "    Answer YES to all questions.\n"
               "\n"
               "  --help\n"
               "    Display this help\n"
               "\n"
               "  --license\n"
               "    Display license\n"
               "\n";
    }
}

std::function<void(int)> shutdown_handler;
void signal_handler(int signal)
{
    shutdown_handler(signal);
}

int main(int argc, char *argv[])
{
    std::size_t num_threads{DefaultNumThreads};
    std::string output_filename(DefaultOutputFilename);
    std::uint32_t first_hash_prefix{0};
    std::uint32_t hash_prefix_step{DefaultHashPrefixStep};
    bool yes = false;
    int verbosity = 0;

    fs::path config_directory{get_home_directory() / fs::path(".hibpdl")};
    if (!fs::is_directory(config_directory))
    {
        fs::create_directory(config_directory);
    }
    fs::path checkpoint_filename = config_directory / fs::path(DefaultCheckpointFilename);

    fs::path lock_filename = config_directory / fs::path(DefaultLockFilename);
    if (fs::exists(lock_filename))
    {
        std::ifstream lock_file(lock_filename);
        std::string pid_str;
        std::getline(lock_file, pid_str);
        about();
        std::cerr
            << "\n\u001b[31;1m<WARNING>\u001b[0m\n"
               "A lock file is present, indicating that `"
            << PROJECT_NAME
            << "`\nis already running with process ID " << pid_str
            << ".\n"
               "If you think that the lock is stale, you can\n"
               "delete "
            << lock_filename
            << " and retry.\n"
               "\u001b[31;1m</WARNING>\u001b[0m\n\n"
               "Do you want to delete the lock file and proceed?\n"
               "[y/n]? ";
        char c;
        std::cin >> c;
        if (c == 'y')
        {
            fs::remove(lock_filename);
        }
        else
        {
            return EXIT_FAILURE;
        }
    }

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
        int c = getopt_long(argc, argv, "?d:t:vy", long_options, &option_index);
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 0:
            if (strcasecmp(optarg, "license") == 0)
            {
                license();
                return EXIT_SUCCESS;
            }
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 't':
            num_threads = static_cast<unsigned int>(atoi(optarg));
            break;
        case 'p':
            first_hash_prefix = std::stoul(optarg, nullptr, 16);
            if (first_hash_prefix > 0xffff)
            {
                std::cerr << "\u001b[31;1mERROR: invalid value, must be less than FFFFh.\u001b[0m" << std::endl;
                return EXIT_FAILURE;
            }
            break;
        case 's':
            hash_prefix_step = std::stoul(optarg, nullptr, 16);
            if (hash_prefix_step > 0x8000)
            {
                std::cerr << "\u001b[31;1mERROR: invalid value, must be less than 8000h.\u001b[0m" << std::endl;
                return EXIT_FAILURE;
            }
            break;
        case 'y':
            yes = true;
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
    if (verbosity > 0)
    {
        about();
    }
    if (verbosity > 1 && !yes)
    {
        std::cout << "Probing for checkpoint file `" << checkpoint_filename << "` ...\n";
    }
    if (fs::exists(checkpoint_filename) && !yes)
    {
        std::string checkpoint_range;
        std::ifstream chkpoint(checkpoint_filename);
        std::getline(chkpoint, checkpoint_range);
        std::string checkpoint_output_filename;
        std::getline(chkpoint, checkpoint_output_filename);
        if (fs::exists(checkpoint_output_filename))
        {
            auto [from, to] = ::util::unpair(checkpoint_range, '-');
            std::cout
                << "Found a checkpoint file stating that the\n"
                   "last saved block ranges from `"
                << std::hex << std::setw(4) << std::setfill('0') << from
                << "` to `"
                << std::hex << std::setw(4) << std::setfill('0') << to
                << "`\n"
                   "and was written to `"
                << checkpoint_output_filename << "`.\n\n"
                << "Do you want to continue from "
                << to
                << "?\n\n"
                   "  (y) to continue from checkpoint.\n"
                   "  (r) to start over from 0000.\n"
                   "  (q) to quit.\n\n"
                   "  or type a 4-digit hex number to continue from there.\n\n"
                   "[y/r/q/number]? ";
            std::string answer;
            std::cin >> answer;
            if (answer == "y")
            {
                first_hash_prefix = std::stoul(to, nullptr, 16);
            }
            else if (answer == "r")
            {
                fs::remove(output_filename);
                fs::remove(checkpoint_filename);
            }
            else if (answer == "q")
            {
                return EXIT_SUCCESS;
            }
            else
            {
                first_hash_prefix = std::stoul(answer, nullptr, 16);
            }
        }
    }

    if (first_hash_prefix != 0x0000)
    {
        if (first_hash_prefix > 0xffff)
        {
            std::cerr << "\u001b[31;1mERROR: invalid value, must be less than ffff.\u001b[0m" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout
            << "OK, continuing from "
            << std::hex << std::setw(4) << std::setfill('0')
            << first_hash_prefix << std::dec << ".\n";
    }
    else if (fs::exists(checkpoint_filename))
    {
        fs::remove(checkpoint_filename);
    }

    std::ofstream lock_file(lock_filename);
    lock_file << getpid();
    lock_file.close();

    bool do_quit = false;
    constexpr std::size_t max_hash_prefix = 1UL << (4 * 4); // 4 nibbles
    for (std::size_t hash_prefix = first_hash_prefix;
         hash_prefix < max_hash_prefix;
         hash_prefix += hash_prefix_step)
    {
        if (verbosity > 0)
        {
            std::cout
                << "Fetching hashes from "
                << std::hex << std::setw(4) << std::setfill('0')
                << hash_prefix << "h to "
                << std::hex << std::setw(4) << std::setfill('0')
                << (hash_prefix + hash_prefix_step - 1) << "h ..."
                << std::endl;
        }
        hibp::downloader hibpdl(hash_prefix, hash_prefix + hash_prefix_step);
        hibpdl.set_verbosity(verbosity);
        std::vector<std::thread> workers;
        workers.reserve(num_threads);
        timer t;
        struct sigaction sigint_handler;
        sigint_handler.sa_handler = signal_handler;
        shutdown_handler = [&hibpdl, &do_quit](int) -> void
        {
            std::cout << "Shutting down ... " << std::endl;
            hibpdl.stop();
            do_quit = true;
        };
        sigemptyset(&sigint_handler.sa_mask);
        sigint_handler.sa_flags = 0;
        sigaction(SIGINT, &sigint_handler, NULL);
        for (std::size_t i = 0; i < num_threads; ++i)
        {
            workers.emplace_back(&hibp::downloader::http_worker, &hibpdl);
        }
        for (auto &worker : workers)
        {
            worker.join();
        }
        if (do_quit)
        {
            std::cout << "Main thread about to exit ..." << std::endl;
            break;
        }
        if (verbosity > 0)
        {
            std::cout << "\n"
                      << "Total time: "
                      << std::dec << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                      << std::endl;
            std::cout << "Sorting " << hibpdl.collection().size() << " entries ..." << std::endl;
        }
        hibp::collection_t const &collection = hibpdl.finalize();
        if (verbosity > 0)
        {
            std::cout << "Total time: "
                      << std::dec << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                      << std::endl;
            std::cout << "\u001b[33;1mWriting " << hibpdl.collection().size() << " entries to '" << output_filename << "' ...\u001b[0m" << std::endl;
        }
        std::ofstream out(output_filename, std::ios::binary | std::ios::app);
        for (auto const &item : collection)
        {
            item.dump(out);
        }
        out.close();
        if (verbosity > 0)
        {
            std::cout << "\u001b[33;1mWriting checkpoint file  '" << checkpoint_filename << "' ...\u001b[0m" << std::endl;
        }
        std::ofstream checkpoint(checkpoint_filename, std::ios::trunc);
        checkpoint
            << std::hex
            << std::setw(4) << std::setfill('0')
            << hash_prefix
            << '-'
            << std::setw(4) << std::setfill('0')
            << (hash_prefix + hash_prefix_step)
            << '\n'
            << output_filename;
        checkpoint.close();
        if (verbosity > 0)
        {
            std::cout << "Total time: "
                      << std::dec << chrono::duration_cast<chrono::milliseconds>(t.elapsed()).count() << " ms"
                      << std::endl;
        }
    }

    if (!do_quit)
    {
        fs::remove(checkpoint_filename);
    }
    fs::remove(lock_filename);
    return EXIT_SUCCESS;
}

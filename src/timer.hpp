#ifndef __TIMER_HPP__
#define __TIMER_HPP__

#include <chrono>

class timer
{
    using clock_type = std::chrono::high_resolution_clock;
    clock_type::time_point t0_;

public:
    using duration = clock_type::duration;

    timer() : t0_(clock_type::now())
    {
    }

    duration elapsed() const
    {
        return clock_type::now() - t0_;
    }
};

#endif // __TIMER_HPP__

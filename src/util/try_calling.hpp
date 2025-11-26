#pragma once

#include <oxen/log.hpp>

#include <exception>
#include <utility>

namespace srouter
{
    namespace log = oxen::log;

    // Calls a function `f` with `args...`, wrapping it in a try/catch that logs an error to `logcat` if
    // the callback throws.  This uses a constructor masquerading as a function call via a deduction
    // guide so that we can deduce arguments while still using a trailing source_location to properly
    // identify the call location in the log.
    template <typename Func, typename... Args>
    struct try_calling
    {
        try_calling(
            const log::logger_ptr& cat,
            Func&& f,
            Args&&... args,
            log::source_location loc = log::source_location::current())
        {
            try
            {
                f(std::forward<Args>(args)...);
            }
            catch (const std::exception& e)
            {
                log::error<const char*>(cat, "Callback raised an uncaught exception: {}", e.what(), loc);
            }
        }
    };

    template <typename Func, typename... Args>
    try_calling(const log::logger_ptr& cat, Func&& f, Args&&... args) -> try_calling<Func, Args...>;

}  // namespace srouter

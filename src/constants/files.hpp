#pragma once

#include <filesystem>

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

namespace srouter
{
    inline const std::filesystem::path our_rc_filename{"self.signed"};
    inline const std::filesystem::path nodedb_dirname{"nodedb"};
    inline const std::filesystem::path default_bootstrap{"bootstrap.signed"};
    inline const std::filesystem::path default_config_filename{"session-router.ini"};

    inline std::filesystem::path GetDefaultDataDir()
    {
#ifndef _WIN32
        if (auto uid = geteuid())
            if (auto* pw = getpwuid(uid))
                return std::filesystem::path{pw->pw_dir} / ".session-router";
        return std::filesystem::current_path();
#else
        return std::filesystem::path{"C:\\ProgramData\\Session-Router"};
#endif
    }

    inline std::filesystem::path GetDefaultConfigPath() { return GetDefaultDataDir() / default_config_filename; }

    inline std::filesystem::path GetDefaultBootstrap() { return GetDefaultDataDir() / default_bootstrap; }

}  // namespace srouter

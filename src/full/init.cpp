#include "full/init.hpp"

#include "config/config.hpp"
#include "util/service_manager.hpp"

namespace srouter::full
{
    void initialize()
    {
        sys::install_native_service_manager();
        config::install_full_config_validators();
    }

}  // namespace srouter::full

#pragma once

#include <string_view>

namespace srouter
{

    /// check if an sns name complies with the registration rules
    bool is_valid_sns(std::string_view sns_name);

}  // namespace srouter

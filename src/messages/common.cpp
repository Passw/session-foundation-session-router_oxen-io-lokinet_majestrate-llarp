#include "common.hpp"

namespace srouter::messages
{

    std::string serialize_status_response(std::string_view value)
    {
        oxenc::bt_dict_producer p;
        p.append(STATUS_KEY, value);
        return std::move(p).str();
    }

    const std::string TIMEOUT_RESPONSE = serialize_status_response(STATUS_TIMEOUT);
    const std::string ERROR_RESPONSE = serialize_status_response(STATUS_ERROR);
    const std::string OK_RESPONSE = serialize_status_response(STATUS_OK);
    const std::string NOT_FOUND_RESPONSE = serialize_status_response(STATUS_NOT_FOUND);

}  // namespace srouter::messages

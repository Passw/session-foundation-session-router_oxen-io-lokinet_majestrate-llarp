#include "srv_data.hpp"

#include "address/address.hpp"
#include "util/formattable.hpp"
#include "util/logging.hpp"
#include "util/str.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/bt_serialize.h>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

    SRVData::SRVData(std::string_view srv_proto, uint16_t priority, uint16_t weight, uint16_t port, std::string target)

        : priority{priority}, weight{weight}, port{port}, target{std::move(target)}
    {
        auto pieces = split(srv_proto, ".");
        if (pieces.size() != 2)
            throw std::invalid_argument{"{} is not a valid _service._proto value"};
        service = pieces[0];
        proto = pieces[1];

        if (not is_valid())
            throw std::invalid_argument{"Invalid SRVData!"};
    }

    SRVData::SRVData(
        std::string service, std::string proto, uint16_t priority, uint16_t weight, uint16_t port, std::string target)

        : service{std::move(service)},
          proto{std::move(proto)},
          priority{priority},
          weight{weight},
          port{port},
          target{std::move(target)}
    {
        if (not is_valid())
            throw std::invalid_argument{"Invalid SRVData!"};
    }

    SRVData::SRVData(oxenc::bt_dict_consumer&& btdc)
    {
        try
        {
            bt_decode(std::move(btdc));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "SRVData parsing exception: {}", e.what());
        }
    }

    bool SRVData::is_valid() const
    {
        auto check_piece = [](std::string_view p) {
            if (p.size() < 2 || !p.starts_with('_'))
                return false;
            p.remove_prefix(1);
            // Upper-case is deliberately excluded because those should have been lower-cased when
            // loaded from the config file.
            if (p.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") != std::string::npos)
                return false;
            return true;
        };
        if (!check_piece(service) || !check_piece(proto))
        {
            log::warning(logcat, "Invalid SRV _service._proto value: {}.{}", service, proto);
            return false;
        }

        // check target size is not absurd
        if (target.size() > TARGET_MAX_SIZE)
        {
            log::warning(logcat, "SRVData target larger than max size ({})", TARGET_MAX_SIZE);
            return false;
        }

        if (target.ends_with(CLIENT_DOT_TLD) || target.ends_with(".loki"))
            return true;

        // A target of just "." in an SRV record is an explicit "does not exist" value:
        if (target == "." or target.size() == 0)
            return true;

        // if we're here, target is invalid
        log::warning(logcat, "SRV target {} is invalid", target);
        return false;
    }

    bool SRVData::from_string(std::string_view srvString)
    {
        log::debug(logcat, "SRVData::fromString(\"{}\")", srvString);

        // split on spaces, discard trailing empty strings
        auto splits = split(srvString, " ", false);

        if (splits.size() != 5)
        {
            log::warning(logcat, "SRV records must have 5 space-separated parts");
            return false;
        }

        if (auto svc_proto = split(splits[0], "."); svc_proto.size() == 2)
        {
            service = svc_proto[0];
            proto = svc_proto[1];
        }
        else
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as _service._proto value", splits[0]);
            return false;
        }

        if (not parse_int(splits[1], priority))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (priority)", splits[1]);
            return false;
        }

        if (not parse_int(splits[2], weight))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (weight)", splits[2]);
            return false;
        }

        if (not parse_int(splits[3], port))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (port)", splits[3]);
            return false;
        }

        target = splits[4];

        return is_valid();
    }

    void SRVData::bt_encode(oxenc::bt_dict_producer&& btdp) const
    {
        btdp.append("p", port);
        btdp.append("s", "{}.{}"_format(service, proto));
        btdp.append("t", target);
        btdp.append("u", priority);
        btdp.append("w", weight);
    }

    std::string SRVData::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;
        bt_encode(std::move(btdp));
        return std::move(btdp).str();
    }

    bool SRVData::bt_decode(std::string buf)
    {
        try
        {
            return bt_decode(oxenc::bt_dict_consumer{buf});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "SRVData parsing exception: {}", e.what());
            return false;
        }
    }

    bool SRVData::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        try
        {
            port = btdc.require<uint16_t>("p");
            auto s_p = split(btdc.require<std::string_view>("s"), ".");
            if (s_p.size() != 2)
                throw std::invalid_argument{"Invalid _service._proto value {}"_format(fmt::join(s_p, "."))};
            service = s_p[0];
            proto = s_p[1];
            target = btdc.require<std::string>("t");
            priority = btdc.require<uint16_t>("u");
            weight = btdc.require<uint16_t>("w");

            return is_valid();
        }
        catch (const std::exception& e)
        {
            auto err = "SRVData parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    std::optional<SRVData> SRVData::from_srv_string(std::string buf)
    {
        if (SRVData ret; ret.from_string(std::move(buf)))
            return ret;

        return std::nullopt;
    }
}  // namespace srouter::dns

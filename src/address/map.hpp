#pragma once

#include "address.hpp"
#include "util/formattable.hpp"
#include "util/thread/threading.hpp"

namespace srouter
{
    template <typename LocalAddrT>
    struct address_map
    {
      protected:
        std::unordered_map<LocalAddrT, NetworkAddress> _local_to_remote;
        std::unordered_map<NetworkAddress, LocalAddrT> _remote_to_local;

        using Lock_t = util::NullLock;
        mutable util::NullMutex addr_mutex;

      public:
        // Inserts a bidirectional mapping between the IP local and the network address remote.
        // Throws if either already exist (the caller should have checked that before calling this).
        void insert(const LocalAddrT& local, const NetworkAddress& remote)
        {
            Lock_t l{addr_mutex};

            if (auto [it, ins] = _local_to_remote.emplace(local, remote); not ins)
                throw std::logic_error{
                    "Unable to add {} -> {} address map: that IP already maps to {}"_format(local, remote, it->second)};
            if (auto [it, ins] = _remote_to_local.emplace(remote, local); not ins)
                throw std::logic_error{"Unable to add {} -> {} address map: that address already maps to {}"_format(
                    remote, local, it->second)};
        }

        std::optional<NetworkAddress> operator[](const LocalAddrT& local) const
        {
            Lock_t l{addr_mutex};

            if (auto itr = _local_to_remote.find(local); itr != _local_to_remote.end())
                return itr->second;
            return std::nullopt;
        }

        std::optional<LocalAddrT> operator[](const NetworkAddress& remote) const
        {
            Lock_t l{addr_mutex};

            if (auto itr = _remote_to_local.find(remote); itr != _remote_to_local.end())
                return itr->second;
            return std::nullopt;
        }

        bool contains(const LocalAddrT& local) const
        {
            Lock_t l{addr_mutex};

            return _local_to_remote.contains(local);
        }

        bool contains(const NetworkAddress& remote) const
        {
            Lock_t l{addr_mutex};

            return _remote_to_local.contains(remote);
        }

        void erase(const NetworkAddress& remote)
        {
            Lock_t l{addr_mutex};

            if (auto it = _remote_to_local.find(remote); it != _remote_to_local.end())
            {
                _local_to_remote.erase(it->second);
                _remote_to_local.erase(it);
            }
        }

        void erase(const LocalAddrT& local)
        {
            Lock_t l{addr_mutex};

            if (auto it_a = _local_to_remote.find(local); it_a != _local_to_remote.end())
            {
                if (auto it_b = _remote_to_local.find(it_a->second); it_b != _remote_to_local.end())
                    _remote_to_local.erase(it_b);
                _local_to_remote.erase(it_a);
            }
        }
    };
}  //  namespace srouter

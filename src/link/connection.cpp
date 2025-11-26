#include "connection.hpp"

#include "util/logging.hpp"

namespace srouter::link
{
    static auto logcat = log::Cat("link_conn");

    Connection::Connection(std::shared_ptr<quic::Connection> c, std::shared_ptr<quic::BTRequestStream> s)
        : conn{std::move(c)}, datagrams{conn->datagrams()}, control_stream{std::move(s)}
    {}

    void Connection::close(uint64_t errcode)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        conn->close_connection(errcode);
    }
}  // namespace srouter::link

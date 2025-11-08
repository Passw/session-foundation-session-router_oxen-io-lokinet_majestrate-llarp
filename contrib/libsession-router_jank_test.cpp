#include <session/router.hpp>

#include <csignal>
#include <exception>
#include <filesystem>
#include <future>
#include <iostream>

extern "C"
{
#include <unistd.h>
}

using namespace std::literals;

int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        std::cerr << "USAGE: " << argv[0] << " {WHATEVER.loki | WHATEVER.snode}\n";
        return 1;
    }

    // Block signal handling by default from all threads, so that we handle signals exclusively in
    // this main thread below.
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    for (auto sig : {SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2})
        sigaddset(&signal_mask, sig);
    pthread_sigmask(SIG_BLOCK, &signal_mask, nullptr);

    std::string target{argv[1]};

    auto srouter = std::make_unique<session::router::SessionRouter>(std::filesystem::path{"jank.ini"});

    std::promise<void> prom;
    std::promise<void> conn_prom;

    bool first_conn = true;
    srouter->on_connected([&] {
        if (!first_conn)
            return;
        first_conn = false;
        std::cout << "\n\x1b[32;1mSession Router connected!\x1b[0m\n\n";
        conn_prom.set_value();
    });
    try
    {
        conn_prom.get_future().get();

        //std::this_thread::sleep_for(500ms);
        std::cout << "\x1b[33;1mINITIATING SESSION TO " << target << "\x1b[0m\n\n" << std::flush;
        srouter->establish_udp(
            target,
            12345,
            [&prom](auto udp_info) {
                std::cout << "\n\x1b[32;1mUDP bound to port [::1]:" << udp_info.local_port << "\x1b[0m\n\n" << std::flush;
                prom.set_value();
            },
            [&prom]() {
                try
                {
                    throw std::runtime_error{"Session timed out!"};
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });

        prom.get_future().get();
        const auto current_path = srouter->get_path_for_session(target);
        if (!current_path)
        {
            std::cerr << "future returned with no session / no current path.\n";
            return 1;
        }
        size_t hop_count = 1;
        std::cout << "Path to snode:\n";
        for (const auto& [snode, ip] : *current_path)
        {
            std::cout << "\tHop " << hop_count << ":\t" << snode << " @ " << ip << "\n";
            hop_count++;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n\n\x1b[31;1m" << e.what() << "\x1b[0m\n\n";
        return 1;
    }

    auto pid = getpid();
    std::cout << "\n\n\x1b[32;1mTunnel running.\n\n"
              << argv[0] << " signal controls:\n\n"
              << "    kill -SIGHUP " << pid << " -- close tunnels\n"
              << "    kill -SIGUSR1 " << pid << " -- re-open UDP tunnel\n"
              << "    kill -SIGUSR2 " << pid << " -- re-open TCP tunnel\n"
              << "    Ctrl-C -- shut down\x1b[0m\n\n\n";

    /*
    srouter.map_tcp_remote_port(std::string{argv[1]}, 12345,
        [&](auto tunnel_info) {
          std::cout << "\n\nTCP bound to port " << tunnel_info.local_port << "\n\n";
        },
        [&](auto error_str) {
          std::cerr << "\nTCP Tunnel map error: " << error_str << "\n";
        });
    */

    std::thread sig_thread{[&] {
        while (srouter)
        {
            int signo;
            sigwait(&signal_mask, &signo);
            switch (signo)
            {
                case SIGHUP:
                    std::cout << "\n\n\n\x1b[33;1mHangup signal received; closing UDP tunnel\x1b[0m\n\n\n";
                    srouter->close_udp(target, 12345);
                    break;
                case SIGUSR1:
                {
                    std::cout << "\n\n\n\x1b[32;1mSIGUSR1 received: (re-)opening UDP tunnel\x1b[0m\n";
                    auto ti = srouter->establish_udp(target, 12345);
                    std::cout << "\n\x1b[32;1mUDP bound to port " << ti.local_port << "\x1b[0m\n\n";
                    break;
                }
                case SIGUSR2:
                    std::cout << "\n\x1b[31;1mSIGUSR2 received: TODO FIXME: reopen TCP tunnel\x1b[0m\n\n";
                    break;
                default:
                    std::cout << "\n\n\n\x1b[33;1mSignal " << signo << " received, shutting down\x1b\[0m\n\n\n";
                    srouter.reset();
                    break;
            }
        }
    }};
    sig_thread.join();
}

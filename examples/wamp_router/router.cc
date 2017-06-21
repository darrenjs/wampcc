/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <iostream>
#include <random>

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#endif

// replace with optional<> if C++17 present
template <typename T> struct user_optional
{
  user_optional& operator=(T v)
  {
    m_value.first = std::move(v);
    m_value.second = true;
    return *this;
  }
  constexpr T& value() const { return m_value.first; }
  T& value() { return m_value.first; }
  constexpr operator bool() const { return m_value.second; }
private:
  std::pair<T,bool> m_value;
};


struct user_options
{
  // setting for the ssl acceptor, if requested
  user_optional<std::string> ssl_addr;
  user_optional<std::string> ssl_port;
} uopts;




int main(int argc, char** argv)
{
  try {
    uopts.ssl_port = "55555";

    std::promise<void> can_exit;

    /* Create the wampcc logger & kernel. */

    //auto logger = wampcc::logger::console();
    auto logger = wampcc::logger::stream(wampcc::logger::lockable_cout,
                                         wampcc::logger::levels_upto(wampcc::logger::eDebug),
                                         true);


    wampcc::config conf;
    conf.ssl.enable = true;
    conf.ssl.certificate_file = "/home/darrens/work/dev/src/c++/wampcc/examples/server.crt";
    conf.ssl.private_key_file = "/home/darrens/work/dev/src/c++/wampcc/examples/server.key";

    std::unique_ptr<wampcc::kernel> the_kernel(
        new wampcc::kernel(conf, logger));

    logger.write(wampcc::logger::eInfo, wampcc::package_string(), __FILE__, __LINE__);

    /* Create an embedded wamp router. */

    wampcc::wamp_router router(the_kernel.get());

    /* Accept SSL clients  */

    /** Generic listen method. Use this option to enable use of SSL, and to have
     * finer control over which WAMP protocols will be permitted.  */
    wampcc::auth_provider auth = wampcc::auth_provider::no_auth_required();
    wampcc::wamp_router::listen_options listen_opts;
    listen_opts.ssl = true;
    listen_opts.service =uopts.ssl_port.value();
    auto fut = router. listen(auth, listen_opts);

    if (fut.wait_for(std::chrono::milliseconds(250)) !=
        std::future_status::ready)
      throw std::runtime_error("timeout during router listen");

    if (auto ec = fut.get())
      throw std::runtime_error("listen failed: err " +
                               std::to_string(ec.os_value()) + ", " +
                               ec.message());

    logger.write(wampcc::logger::eInfo,
                 "ssl socket listening on " + uopts.ssl_port.value(),
                 __FILE__, __LINE__);

    /* Provide several RPCs */

    router.provide("default_realm", "greeting", {},
                   [](wampcc::wamp_invocation& invocation) {
      invocation.yield({"hello"});
    });

    router.provide("default_realm", "pid", {},
                   [](wampcc::wamp_invocation& invocation) {
      invocation.yield({getpid()});
    });

    /* Demonstrate sending an error as the RPC result. */
    router.provide("default_realm", "stop", {},
                   [&can_exit](wampcc::wamp_invocation& invocation) {
                     can_exit.set_value();
    });

    /* Suspend main thread */
    can_exit.get_future().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

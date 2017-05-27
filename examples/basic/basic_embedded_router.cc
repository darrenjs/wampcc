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

int main(int argc, char** argv)
{
  try {
    int port = 55555;
    if (argc >1)
      port = std::stoi(argv[1]);

    /* Create the wampcc logger & kernel. */

    auto logger = wampcc::logger::stream(
        std::cout, wampcc::logger::levels_upto(wampcc::logger::eInfo), false);
    std::unique_ptr<wampcc::kernel> the_kernel(
        new wampcc::kernel({}, std::move(logger)));

    /* Create an embedded wamp router. */

    wampcc::wamp_router router(the_kernel.get());

    /* Accept clients on IPv4 port, without authentication. */

    auto fut = router.listen(wampcc::auth_provider::no_auth_required(), port);

    if (fut.wait_for(std::chrono::milliseconds(250)) !=
        std::future_status::ready)
      throw std::runtime_error("timeout during router listen");

    if (auto ec = fut.get())
      throw std::runtime_error("listen failed: err " +
                               std::to_string(ec.os_value()) + ", " +
                               ec.message());

    the_kernel->get_logger().write(wampcc::logger::eInfo,
                                   "listening on " + std::to_string(port),
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

    router.provide("default_realm", "random_string", {},
                   [](wampcc::wamp_invocation& invocation) {
      std::mt19937 engine((int)std::random_device()());
      std::uniform_int_distribution<> distr(0, 100);
      invocation.yield({distr(engine)});
    });

    /* Demonstrate sending an error as the RPC result. */
    router.provide("default_realm", "kill", {},
                   [](wampcc::wamp_invocation& invocation) {
      invocation.error("not implemented");
    });

    /* Suspend main thread */
    std::promise<void> forever;
    forever.get_future().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

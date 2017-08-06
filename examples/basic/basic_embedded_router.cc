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

    std::promise<void> can_exit;

    /* Create the wampcc logger & kernel. */

    auto logger = wampcc::logger::console();
    // auto logger = wampcc::logger::stream(wampcc::logger::lockable_cout, wampcc::logger::levels_upto(wampcc::logger::eDebug), true);
    std::unique_ptr<wampcc::kernel> the_kernel(
        new wampcc::kernel({}, logger));

    logger.write(wampcc::logger::eInfo, wampcc::package_string(),
                 __FILE__, __LINE__);

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

    logger.write(wampcc::logger::eInfo,
                 "listening on " + std::to_string(port),
                 __FILE__, __LINE__);

    /* Provide several RPCs */

    router.callable("default_realm", "greeting",
                    [](wampcc::wamp_router&, wampcc::wamp_session& ws, wampcc::call_info info) {
                      ws.result(info.request_id, {"hello"});
                    });

    router.callable("default_realm", "pid",
                    [](wampcc::wamp_router&, wampcc::wamp_session& ws, wampcc::call_info info) {
                      ws.result(info.request_id, {getpid()});
                    });

    router.callable("default_realm", "random_string",
                    [](wampcc::wamp_router&, wampcc::wamp_session& ws, wampcc::call_info info) {
                      std::mt19937 engine((int)std::random_device()());
                      std::uniform_int_distribution<> distr(0, 100);
                      ws.result(info.request_id, {distr(engine)});
                    });

    /* Demonstrate sending an error as the RPC result. */
    router.callable("default_realm", "kill",
                    [](wampcc::wamp_router&,wampcc::wamp_session& ws ,wampcc::call_info info) {
                      ws.call_error(info.request_id, "not implemented");
                    });

    /* Demonstrate sending an error as the RPC result. */
    router.callable("default_realm", "stop",
                    [&can_exit](wampcc::wamp_router&,wampcc::wamp_session&,wampcc::call_info) {
                      can_exit.set_value();
                    });

    /* Suspend main thread */
    can_exit.get_future().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

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
    if (argc < 4) {
      std::cout << "required args: SSL_CERT_FILE SSL_KEY_FILE PORT" << std::endl;
      return 1;
    }
    std::string ssl_port = argv[3];

    std::promise<void> can_exit;

    /* Create the wampcc logger & kernel. */

    //auto logger = wampcc::logger::console();
    auto logger = wampcc::logger::stream(wampcc::logger::lockable_cout,
                                         wampcc::logger::levels_upto(wampcc::logger::eDebug),
                                         true);


    wampcc::config conf;
    conf.ssl.enable = true;
    conf.ssl.certificate_file = argv[1];
    conf.ssl.private_key_file = argv[2];

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
    listen_opts.service = ssl_port;
    auto fut = router. listen(auth, listen_opts);

    if (fut.wait_for(std::chrono::milliseconds(250)) !=
        std::future_status::ready)
      throw std::runtime_error("timeout during router listen");

    if (auto ec = fut.get())
      throw std::runtime_error("listen failed: err " +
                               std::to_string(ec.os_value()) + ", " +
                               ec.message());

    logger.write(wampcc::logger::eInfo,
                 "ssl socket listening on " + ssl_port,
                 __FILE__, __LINE__);

    /* Provide several RPCs */

    router.callable("default_realm", "greeting",
                    [](wampcc::wamp_router&, wampcc::wamp_session& caller, wampcc::call_info info) {
                      caller.result(info.request_id, {"hello"});
                    });

    router.callable("default_realm", "pid",
                    [](wampcc::wamp_router&, wampcc::wamp_session& caller, wampcc::call_info info) {
                      caller.result(info.request_id, {getpid()});
                    });

    /* Demonstrate sending an error as the RPC result. */
    router.callable("default_realm", "stop",
                    [&can_exit](wampcc::wamp_router&, wampcc::wamp_session&, wampcc::call_info) {
                      can_exit.set_value();
                    });

    /* Suspend main thread */
    can_exit.get_future().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

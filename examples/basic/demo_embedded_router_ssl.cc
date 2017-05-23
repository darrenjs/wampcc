/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <iostream>

using namespace wampcc;
using namespace std;

int main(int argc, char** argv)
{
  try
  {
    if (argc < 2)
      throw runtime_error("required args: PORT");

    /* Create the wampcc kernel, configured to use SSL/TLS and support server
     * mode via the presence of a certificate & key. */

    config cfg;
    cfg.ssl.enable = true;
    cfg.ssl.certificate_file = "server.crt";
    cfg.ssl.private_key_file = "server.key";

    kernel the_kernel(cfg, logger::console());

    /* Create an embedded wamp router. */

    wamp_router router(&the_kernel);

    /* Create the listen socket configuration, to support SSL/TLS and all
     * available protocols & message formats. */
    wamp_router::listen_options opts;
    opts.flags = wamp_router::listen_options::ssl |
      wamp_router::listen_options::all_sockets |
      wamp_router::listen_options::all_formats;
    opts.service=argv[1];
    opts.af = tcp_socket::addr_family::inet4;

    /* Accept clients without authentication, using the SSL/TLS
     * configuration. */

    auto fut = router.listen(auth_provider::no_auth_required(), opts);

    if (auto ec = fut.get())
      throw runtime_error(ec.message());

    /* Provide an RPC named 'greeting' on realm 'default_realm'. */

    router.provide(
        "default_realm", "greeting", {},
        [](wamp_invocation& invocation) { invocation.yield({"hello SSL"}); });

    /* Suspend main thread */

    pause();
  } catch (const exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

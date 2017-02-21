/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <memory>
#include <iostream>

using namespace wampcc;

int main(int argc, char** argv)
{
  try {
    /* Create the wampcc kernel. */

    kernel my_kernel({}, logger::stdout());

    /* Create the TCP socket and attempt to connect. */

    std::unique_ptr<tcp_socket> my_socket(new tcp_socket(&my_kernel));
    my_socket->connect("127.0.0.1", 55555).wait_for(std::chrono::seconds(3));

    if (not my_socket->is_connected())
      throw std::runtime_error("connect failed");

    /* With the connected socket, create a wamp session & logon to the realm
     * called 'default_realm'. */

    std::shared_ptr<wamp_session> my_session = wamp_session::create<rawsocket_protocol>(
      &my_kernel,
      std::move(my_socket),
      [](session_handle, bool) { /* handle on-close */ }, {});

    my_session->initiate_hello({"default_realm"}).wait_for(std::chrono::seconds(3));

    if (not my_session->is_open())
      throw std::runtime_error("realm logon failed");

    /* Register a procedure than can sum an array of numbers. */

    my_session->provide(
      "math.service.add", {},
      [](wamp_invocation& invoke){
        int total = 0;
        for (auto & item : invoke.args.args_list)
          if (item.as_int())
            total += item.as_int();
        invoke.yield({total}, {});
      });

    /* Call a remote procedure. */

    my_session->call(
      "math.service.add", {}, {{100,200},{}},
      [](wamp_call_result result) {
        if (result)
          std::cout << "got result: " << result.args.args_list[0] << std::endl;
      });

    return 0;
  }
  catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

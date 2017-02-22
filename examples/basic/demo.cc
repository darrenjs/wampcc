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

    kernel the_kernel({}, logger::stdout());

    /* Create the TCP socket and attempt to connect. */

    std::unique_ptr<tcp_socket> socket(new tcp_socket(&the_kernel));
    socket->connect("127.0.0.1", 55555).wait_for(std::chrono::seconds(3));

    if (not socket->is_connected())
      throw std::runtime_error("connect failed");

    /* With the connected socket, create a wamp session & logon to the realm
     * called 'default_realm'. */

    auto session = wamp_session::create<rawsocket_protocol>(
      &the_kernel,
      std::move(socket),
      [](session_handle, bool) { /* handle on-close */ }, {});

    session->initiate_hello({"default_realm"}).wait_for(std::chrono::seconds(3));

    if (not session->is_open())
      throw std::runtime_error("realm logon failed");

    /* Subscribe to a topic. */

    session->subscribe(
      "random_number", {},
      [](wamp_subscribed& subscribed) {
        std::cout << "subscribed " << (subscribed?"ok":"failed") << std::endl;
      },
      [](wamp_subscription_event ev) {
        for (auto & x : ev.args.args_list)
          std::cout << "got update: " << x << " ";
        std::cout << std::endl;
      });

    /* Register a procedure than can sum an array of numbers. */

    session->provide(
      "math.service.add", {},
      [](wamp_invocation& invoke){
        int total = 0;
        for (auto & item : invoke.args.args_list)
          if (item.as_int())
            total += item.as_int();
        invoke.yield({total}, {});
      });

    /* Call a remote procedure. */

    session->call(
      "math.service.add", {}, {{100,200},{}},
      [](wamp_call_result result) {
        if (result)
          std::cout << "got result: " << result.args.args_list[0] << std::endl;
      });

    /* Publish to a topic. */

    std::srand(std::time(0)); //use current time as seed for random generator
    int random_variable = std::rand();
    session->publish("random_number", {}, {{random_variable},{}});

    /* Stay connected for short while. Either the server may disconnect us, or
     * after a period has elapsed we terminate the session.  */

    session->closed_future().wait_for(std::chrono::minutes(10));
    session->close().wait();

    return 0;
  }
  catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

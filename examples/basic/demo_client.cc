
/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <memory>
#include <iostream>

int main(int argc, char** argv)
{
  try {
    /* Create the wampcc kernel. */

    wampcc::kernel the_kernel;

    /* Create the TCP socket and attempt to connect. */

    std::unique_ptr<wampcc::tcp_socket> socket(new wampcc::tcp_socket(&the_kernel));
    socket->connect("127.0.0.1", 55555).wait_for(std::chrono::seconds(3));

    if (!socket->is_connected())
      throw std::runtime_error("connect failed");

    /* With the connected socket, create a wamp session & logon to the realm
     * called 'default_realm'. */

    auto session = wampcc::wamp_session::create<wampcc::websocket_protocol>(&the_kernel,
                                                                            std::move(socket));

    session->hello("default_realm").wait_for(std::chrono::seconds(3));

    if (!session->is_open())
      throw std::runtime_error("realm logon failed");

    /* Subscribe to a topic. */

    session->subscribe("random_number", {},
                       [](wampcc::wamp_session&, wampcc::subscribed_info info) {
                         std::cout << "subscribed " << (info ? "ok" : "failed")
                                   << std::endl;
                       },
                       [](wampcc::wamp_session&, wampcc::event_info info) {
                         for (auto& x : info.args.args_list)
                           std::cout << "got update: " << x << " ";
                         std::cout << std::endl;
                       });

    /* Register a procedure that can sum an array of numbers. */

    session->provide("math.service.add", {},
                     [](wampcc::wamp_session&, wampcc::registered_info info) {
                       if (info)
                         std::cout << "procedure registered with id "
                                   << info.registration_id << std::endl;
                       else
                         std::cout << "procedure registration failed, error "
                                   << info.error_uri << std::endl;
                     },
                     [](wampcc::wamp_session& ws, wampcc::invocation_info info) {
                       int total = 0;
                       for (auto& item : info.args.args_list)
                         if (item.is_int())
                           total += item.as_int();
                       ws.yield(info.request_id, {total});
                     });

    /* Call a remote procedure. */

    session->call("math.service.add", {}, {{100, 200}, {}},
                  [](wampcc::wamp_session&, wampcc::result_info result) {
      if (result)
        std::cout << "got result: " << result.args.args_list[0] << std::endl;
    });

    /* Publish to a topic. */

    std::srand(std::time(0)); // use current time as seed for random generator
    int random_variable = std::rand();
    session->publish("random_number", {}, {{random_variable}, {}});

    /* Stay connected for short while. Either the server may disconnect us, or
     * after a period has elapsed we terminate the session.  */

    session->closed_future().wait_for(std::chrono::minutes(10));
    session->close().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

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
  try
  {
    if (argc < 3)
      throw std::runtime_error("arguments must be: ADDR PORT RPC_URI (RPC_URI defaults to 'greeting')");
    const char* host = argv[1];
    int port = std::stoi(argv[2]);
    std::string rpc_uri = (argc > 3)? argv[3]:"greeting";
    /* Create the wampcc kernel, which provides event and IO threads. */

    std::unique_ptr<kernel> the_kernel(new kernel({}, logger::console()));

    /* Create the TCP socket and attempt to connect. */

    std::unique_ptr<tcp_socket> sock(new tcp_socket(the_kernel.get()));
    auto fut = sock->connect(host, port);

    if (fut.wait_for(std::chrono::milliseconds(250)) != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    if (uverr ec = fut.get())
      throw std::runtime_error("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());

    /* Using the connected socket, now create the wamp session object. */

    std::promise<void> ready_to_exit;
    std::shared_ptr<wamp_session> session = wamp_session::create<websocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&ready_to_exit](wamp_session&, bool is_open) {
        if (!is_open)
          try {
            ready_to_exit.set_value();
          }
          catch (...) { /* ignore promise already set error */ }
      }, {});

    /* Logon to a WAMP realm, and wait for session to be deemed open. */

    client_credentials credentials;
    credentials.realm="private_realm";
    credentials.authid="tony";
    credentials.authmethods = {"ticket"};
    credentials.ticket_fn = []() -> std::string { return "secret-ticket"; };

    auto logon_fut = session->hello(credentials);

    if (logon_fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
      throw std::runtime_error("time-out during session logon");

    if(!session->is_open())
      throw std::runtime_error("session logon failed");

    /* Session is now open, call a remote procedure. */

    wamp_args call_args;

    /* Note, disclose_me is not mendatory but will return an exception if
     * if the router does not allow dislosure */
    session->call(rpc_uri, {}, call_args,
                  [&ready_to_exit](wampcc::wamp_session&, result_info r) {
                    try {
                      if(r.was_error) {
                        std::cout << "error: " << r.error_uri << std::endl;
                      } else {
                        std::cout << "result: " << r.args.args_list << std::endl;
                      }

                      ready_to_exit.set_value();
                    } catch (...) { /* ignore promise already set error */}
                  });

    /* Wait for RPC completion or until wamp session is closed. */

    ready_to_exit.get_future().wait();
    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

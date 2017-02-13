/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/kernel.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/wamp_session.h"
#include "wampcc/websocket_protocol.h"

#include <memory>
#include <iostream>

using namespace wampcc;

int main(int, char**)
{
  try
  {
    std::unique_ptr<kernel> the_kernel( new wampcc::kernel({}, logger::nolog() ));

    std::unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    auto fut = sock->connect("127.0.0.1", 55555);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    wampcc::uverr ec = fut.get();
    if (ec)
      throw std::runtime_error("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());

    std::promise<void> ready_to_exit;

    std::shared_ptr<wamp_session> session = wamp_session::create<websocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&ready_to_exit](wampcc::session_handle, bool is_open){
        if (!is_open)
          try {
            ready_to_exit.set_value();
          } catch (...) {}
      },
      {});

    /* Logon to a WAMP realm, and wait for session to be deemed open. */
    client_credentials credentials;
    credentials.realm="default_realm";
    credentials.authid="peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn = []() -> std::string { return "secret2"; };

    auto session_open_fut = session->initiate_hello(credentials);

    if (session_open_fut.wait_for(std::chrono::milliseconds(5000)) == std::future_status::timeout)
      throw std::runtime_error("time-out during session logon");

    /* Session is now open, call a remote procedure. */
    wamp_args call_args;
    call_args.args_list = jalson::json_array({"hello from basic_caller"});
    session->call("greeting", {}, call_args, [&ready_to_exit](wamp_call_result){
        try {
        ready_to_exit.set_value();
        } catch (...) {}
      });

    ready_to_exit.get_future().wait();
    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}


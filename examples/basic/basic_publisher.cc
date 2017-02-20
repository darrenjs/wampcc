/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <memory>
#include <random>
#include <iostream>

using namespace wampcc;

std::tuple<std::string, int> get_addr_port(int argc, char** argv)
{
  if (argc != 3)
    throw std::runtime_error("arguments must be: ADDR PORT");
  return std::tuple<std::string,int>(argv[1], std::stoi(argv[2]));
}

int main(int argc, char** argv)
{
  try
  {
    auto endpoint = get_addr_port(argc, argv);

    /* Create the wampcc kernel, which provides event and IO threads. */

    std::unique_ptr<kernel> the_kernel( new wampcc::kernel({}, logger::nolog() ));

    /* Create the TCP socket and attempt to connect. */

    std::unique_ptr<tcp_socket> sock(new tcp_socket(the_kernel.get()));
    auto fut = sock->connect(std::get<0>(endpoint), std::get<1>(endpoint));

    if (fut.wait_for(std::chrono::milliseconds(250)) != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    if (wampcc::uverr ec = fut.get())
      throw std::runtime_error("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());

    /* Using the connected socket, now create the wamp session object. */

    std::promise<void> ready_to_exit;

    std::shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&ready_to_exit](wampcc::session_handle, bool is_open){
        if (!is_open)
          try {
            ready_to_exit.set_value();
          } catch (...) {/* ignore promise already set error */}
      },
      {});

    /* Logon to a WAMP realm, and wait for session to be deemed open. */

    client_credentials credentials;
    credentials.realm="default_realm";
    credentials.authid="peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn = []() -> std::string { return "secret2"; };

    auto logon_fut = session->initiate_hello(credentials);

    if (logon_fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
      throw std::runtime_error("time-out during session logon");

    if(!session->is_open())
      throw std::runtime_error("session logon failed");

    /* Session is now open, publish to a topic. */

    std::vector<std::string> coin_sides({"heads", "tails"});
    std::random_device rd;
    std::mt19937 engine( rd() );
    std::uniform_int_distribution<> distr(0, coin_sides.size()-1);
    auto exit_fut = ready_to_exit.get_future();

    while ( exit_fut.wait_for(std::chrono::milliseconds(500)) != std::future_status::ready )
    {
      wamp_args args({{coin_sides[distr(engine)]}});
      session->publish("coin_toss", {}, std::move(args)); // publish to topic "coin_toss"
    }

    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

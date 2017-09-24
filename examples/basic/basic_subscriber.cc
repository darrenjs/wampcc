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
#include <random>
#include <iostream>

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

    std::unique_ptr<wampcc::kernel> the_kernel( new wampcc::kernel({}, wampcc::logger::console() ));

    std::unique_ptr<wampcc::tcp_socket> sock (new wampcc::tcp_socket(the_kernel.get()));
    auto fut = sock->connect(std::get<0>(endpoint), std::get<1>(endpoint));
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    wampcc::uverr ec = fut.get();
    if (ec)
      throw std::runtime_error("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());


    std::mutex session_closed_mutex;
    std::condition_variable session_closed_convar;
    bool session_has_closed = false;

    std::shared_ptr<wampcc::wamp_session> session = wampcc::wamp_session::create<wampcc::websocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&](wampcc::wamp_session&, bool is_open){
        if (!is_open)
          try {
            std::lock_guard<std::mutex> guard(session_closed_mutex);
            session_has_closed = true;
            session_closed_convar.notify_one();
          } catch (...) {}
      },
      {});

    /* Logon to a WAMP realm, and wait for session to be deemed open. */
    wampcc::client_credentials credentials;
    credentials.realm="default_realm";
    credentials.authid="peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn = []() -> std::string { return "secret2"; };

    auto session_open_fut = session->hello(credentials);

    if (session_open_fut.wait_for(std::chrono::milliseconds(5000)) == std::future_status::timeout)
      throw std::runtime_error("time-out during session logon");

    /* Session is now open, subscribe to a topic. */
    bool have_subscription = false;
    wampcc::t_subscription_id subscription_id = 0;
    std::string uri = "coin_toss";
    wampcc::on_subscribed_fn my_on_subscribed_fn = [&](wampcc::wamp_session&, wampcc::subscribed_info info) {
      if (info)
      {
        have_subscription = true;
        subscription_id = info.subscription_id;
        std::cout << "subscription successful for '"<< uri
                  << "', subscription_id " << subscription_id << std::endl;
      }
      else
      {
        std::cout << "subscription failed for '"<< uri
                   << "', error: " << info.error_uri << std::endl;
        session->close();
      }
    };
    session->subscribe(uri, {},
                       my_on_subscribed_fn,
                       [](wampcc::wamp_session&, wampcc::event_info ev){
                         for (auto & x : ev.args.args_list)
                           std::cout << x << " ";
                         std::cout << std::endl;
                       });

    /* Opps! This is a duplicate subscription.  This is okay; we will actually
     * only subscribe once. */
    session->subscribe(uri, {},
                       my_on_subscribed_fn,
                       [](wampcc::wamp_session&, wampcc::event_info ev){
                         for (auto & x : ev.args.args_list)
                           std::cout << x << " ";
                         std::cout << std::endl;
                       });

    /* stay subscribed for a short interval */
    {
      std::unique_lock<std::mutex> guard(session_closed_mutex);
      session_closed_convar.wait_for(guard, std::chrono::seconds(30),
                                     [&](){ return session_has_closed; });
    }

    /* If we still have an open session, then now unsubscribe. This is to
     * demonstrate use of the unsubscribe interaction. */
    if (session->is_open() && have_subscription)
    {
      std::cout << "doing unsubscribe\n";
      session->unsubscribe(
        subscription_id,
        [](wampcc::wamp_session&, wampcc::unsubscribed_info info)
        {
          if (info)
            std::cout << "unsubscribed ok" << std::endl;
          else
            std::cout << "unsubscribed failed, " << info.error_uri << std::endl;
        });
    }

    /* wait for session to be closed by peer */
    {
      std::unique_lock<std::mutex> guard(session_closed_mutex);
      session_closed_convar.wait(guard, [&](){ return session_has_closed; });
    }

    /* cleanly shutdown the session */
    session->close().wait();

    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

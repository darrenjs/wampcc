/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/*

Commented-out, until tcp_socket supports async callback for on_connect.

 */


#include "wampcc/kernel.h"
#include "wampcc/websocket_protocol.h"
#include "wampcc/wamp_session.h"
#include "wampcc/websocket_protocol.h"

#include <memory>
#include <iostream>

using namespace wampcc;


// std::promise<void> g_exit_value;
// std::shared_ptr<wamp_session> g_session;


// void rpc(wamp_invocation& invoke)
// {
//   invoke.yield( jalson::json_array({"hello", "world"}), {}  );
// }


// void on_wamp_session_status(wampcc::session_handle session, bool is_open)
// {
//   if (is_open)
//     g_session->provide("greeting", jalson::json_object(), rpc);
//   else
//     g_exit_value.set_value();
// }


// void on_wamp_connector_completed(std::shared_ptr<wamp_connector> wconn)
// {
//   try
//   {
//     g_session = wconn->create_session<websocket_protocol>( on_wamp_session_status );

//     client_credentials credentials;
//     credentials.realm="default_realm";
//     credentials.authid="peter";
//     credentials.authmethods = {"wampcra"};
//     credentials.secret_fn = [](){ return std::string("secret2"); };

//     g_session->hello(credentials);
//   }
//   catch (std::exception& e)
//   {
//     g_exit_value.set_exception( std::current_exception() );
//   }
// }


int main(int, char**)
{
  try {

    // std::unique_ptr<kernel> the_kernel( new wampcc::kernel({}, logger::nolog() ));

    // wamp_connector::create(the_kernel.get(),
    //                        "127.0.0.1", "55555",
    //                        false,
    //                        on_wamp_connector_completed);

    // auto fut = g_exit_value.get_future();
    // fut.wait();
    // fut.get();
    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}


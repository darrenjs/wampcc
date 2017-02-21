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

/* The end RPC function that gets invoked via a wamp instruction received from a
 * wamp dealer. */
void rpc(wamp_invocation& invoke)
{
  invoke.yield( json_array({"hello", "world"}), {} );
}

int main(int argc, char** argv)
{

  /* Create the wampcc kernel */

  kernel my_kernel({}, logger::stdout());

  /* Create the TCP socket and attempt to connect */

  std::unique_ptr<tcp_socket> my_socket(new tcp_socket(&my_kernel));
  my_socket->connect("127.0.0.1", 55555).wait();

  /* If socket is connected, create a wamp session */
  if (my_socket->is_connected())
  {
    std::shared_ptr<wamp_session> my_session = wamp_session::create<rawsocket_protocol>(
        &my_kernel,
        std::move(my_socket),
        [](session_handle, bool) { /* handle on-close */ }, {});

    /* Register a procedure than can sum an array of numbers */
    my_session->provide(
      "math.service.add", {},
      [](wamp_invocation& invoke){
        int total = 0;
        for (auto & item : invoke.args.args_list)
          if (item.as_int())
            total += item.as_int();
        invoke.yield({total}, {});
      }
      );

    my_session->call(
      "math.service.add", {}, {{100,200},{}},
      [](wamp_call_result result) {
        if (result)
          std::cout << "got result: " << result.args.args_list[0] << std::endl;
      });


  }


}

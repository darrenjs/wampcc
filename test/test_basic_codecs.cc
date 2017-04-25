/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;

/*

Perform basic RPC test using the full range of protocols supported by wampcc.

*/


std::shared_ptr<internal_server> create_server(int options, int & port)
{
  std::shared_ptr<internal_server> iserver( new internal_server(logger::stdlog(std::cout,
                                                              logger::levels_upto(logger::eTrace)
                                             )) );

  port = iserver->start(port);

  if (port) {
    iserver->router()->provide(
      "default_realm",
      "math.add", {},
      [](wamp_invocation& invoke){
        int total = 0;
        for (auto & item : invoke.args.args_list)
          if (item.is_int())
            total += item.as_int();
        invoke.yield({total});
      });
  }

  return iserver;
}


void run_test_expect_success(establsh_options client_protocol,
                             serialiser client_serialiser,
                             int & port)
{
  // create the server
  std::shared_ptr<internal_server> server = create_server(0, port);

  // create the client
  unique_ptr<kernel> the_kernel(new kernel({},
                                           logger::stdlog(std::cout,
                                                          logger::levels_upto(logger::eTrace)
                                             )));
  auto session = establish_session(the_kernel, port,
                                   client_protocol,
                                   static_cast<int>(client_serialiser));
  perform_realm_logon(session);

  wamp_args call_args;
  call_args.args_list = json_array({1,2,3,4,5});

  wamp_call_result result = sync_rpc_all(session, "math.add", call_args,
                                         rpc_result_expect::success);

  int value = result.args.args_list[0].as_int();

  session->close().wait();

  if (value != 15)
    throw std::runtime_error("call failed");
}


void run_tests(int & port)
{
  run_test_expect_success(establsh_options::websocket, serialiser::json, port);
  port++;
  run_test_expect_success(establsh_options::rawsocket, serialiser::json, port);
  port++;
}


int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 25000;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    run_tests(starting_port_number);

  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

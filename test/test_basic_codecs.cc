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


vector<protocol_type> protocols {protocol_type::websocket, protocol_type::rawsocket};
vector<serialiser_type> serialisers {serialiser_type::json, serialiser_type::msgpack};



std::shared_ptr<internal_server> create_server(int & port,
                                               int allowed_protocols = wampcc::all_protocols,
                                               int allowed_serialisers = wampcc::all_serialisers)
{
  std::shared_ptr<internal_server> iserver(new internal_server(trace_logger()));

  port = iserver->start(port, allowed_protocols, allowed_serialisers);

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




void run_test_expect_success(protocol_type client_protocol,
                             serialiser_type client_serialiser,
                             int & port)
{
  // create the server
  std::shared_ptr<internal_server> server = create_server(port);

  // create the client
  unique_ptr<kernel> the_kernel(new kernel({},trace_logger()));
  auto session = establish_session(the_kernel, port,
                                   static_cast<int>(client_protocol),
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


void run_test_against_server(std::shared_ptr<internal_server>& server,
                             protocol_type client_protocol,
                             serialiser_type client_serialiser,
                             bool expect_success)
{
  bool actual_result = false;

  // create the client
  unique_ptr<kernel> the_kernel(new kernel({}, trace_logger()));

  try {
    auto session = establish_session(the_kernel, server->port(),
                                     static_cast<int>(client_protocol),
                                     static_cast<int>(client_serialiser));
    perform_realm_logon(session);

    wamp_args call_args;
    call_args.args_list = json_array({1,2,3,4,5});

    wamp_call_result result = sync_rpc_all(session, "math.add", call_args,
                                           rpc_result_expect::success);

    int value = result.args.args_list[0].as_int();

    session->close().wait();

    if (value == 15)
      actual_result = true;
  }
  catch (std::exception&e) {
    cout << "exception: " << e.what() << endl;
  }

  if (actual_result && !expect_success)
    throw runtime_error("run_test_against_server passed but expected fail");
  if (!actual_result && expect_success)
    throw runtime_error("run_test_against_server failed but expected pass");
}


void run_tests_against_null_server(int& port)
{
  /* configure & create a server that supports no protocols  */
  auto server = create_server(port,0,0);

  /* launch tests against it */
  for (auto pt : protocols)
    for (auto st : serialisers) {
      run_test_against_server(server, pt, st, false);
    }
}


void run_tests(int & port)
{
  run_tests_against_null_server(port);
  port++;
  run_test_expect_success(protocol_type::websocket, serialiser_type::json, port);
  port++;
  run_test_expect_success(protocol_type::rawsocket, serialiser_type::json, port);
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

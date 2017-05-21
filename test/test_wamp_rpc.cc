/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;


void test_rpc(int port, internal_server& server)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  server.router()->provide("default_realm", "hello", {},
                           [](wampcc::wamp_invocation& invocation) {
                             invocation.yield({"hello"});
                           });
  server.router()->provide("default_realm", "echo", {},
                           [](wampcc::wamp_invocation& invocation) {
                             invocation.yield(invocation.args.args_list,
                                              invocation.args.args_dict);
                           });

  unique_ptr<kernel> the_kernel(new kernel({}, logger::console()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  wamp_args call_args;
  call_args.args_list = json_array({"hello from basic_caller"}, {});

  wamp_call_result result = sync_rpc_all(session, "echo", call_args,
                                         rpc_result_expect::success);

  if (result.args.args_list != call_args.args_list)
    throw runtime_error("call result-list does not match expected");

  if (result.args.args_dict != call_args.args_dict)
    throw runtime_error("call result-dict does not match expected");

  result = sync_rpc_all(session, "hello", {}, rpc_result_expect::success);

  if (result.args.args_list != json_array({"hello"}))
    throw runtime_error("call result-list does not match expected");

  session->close().wait();
}

void test_call_non_existing_rpc(int port, internal_server& server)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  unique_ptr<kernel> the_kernel(new kernel({}, logger::console()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  wamp_call_result result = sync_rpc_all(session, "xxNOTFOUNDxx", {},
                                         rpc_result_expect::fail);

  if (result.error_uri != WAMP_ERROR_URI_NO_SUCH_PROCEDURE)
    throw runtime_error("actual error_uri doesn't match expected");

  session->close().wait();
}

int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 25000;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    auto all_tests = [](int port, internal_server& server)
      {
        test_rpc(port, server);
        test_call_non_existing_rpc(port, server);
      };

    // one-off test
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port, iserver);
    }

    // share a common internal_server
    for (int i = 0; i < 50; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port, iserver);

      // TODO: to enable this, need to remove the procedure
      // for (int j=0; j < 100; j++)
      //   all_tests(port, iserver);
    }

    // use one internal_server per test
    for (int i = 0; i < 500; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port, iserver);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

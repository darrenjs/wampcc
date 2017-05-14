/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 500;

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

  unique_ptr<kernel> the_kernel(new kernel({}, logger::stdout()));
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

  unique_ptr<kernel> the_kernel(new kernel({}, logger::stdout()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  wamp_call_result result = sync_rpc_all(session, "xxNOTFOUNDxx", {},
                                         rpc_result_expect::fail);

  if (result.error_uri != WAMP_ERROR_URI_NO_SUCH_PROCEDURE)
    throw runtime_error("actual error_uri doesn't match expected");

  session->close().wait();
}

auto all_tests = [](int port, internal_server& server)
{
  test_rpc(port, server);
  test_call_non_existing_rpc(port, server);
};

TEST_CASE("test_all")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  all_tests(port, iserver);
}

TEST_CASE("test_all_bulk")
{

  // share a common internal_server
  for (int i = 0; i < global_loops; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);
    all_tests(port, iserver);

    // TODO: to enable this, need to remove the procedure
    // for (int j=0; j < 100; j++)
    //   all_tests(port, iserver);
  }
}

int main(int argc, char** argv)
{
  try
  {
    global_port = 26000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return result < 0xFF ? result : 0xFF;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

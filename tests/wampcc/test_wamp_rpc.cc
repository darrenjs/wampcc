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

  server.router()->callable("default_realm", "hello",
                            [](wampcc::wamp_router& rtr,
                               wampcc::wamp_session& caller,
                               wampcc::call_info info) {
                              caller.result(info.request_id, {"hello"});
                            });
  server.router()->callable("default_realm", "echo",
                            [](wampcc::wamp_router& rtr,
                               wampcc::wamp_session& caller,
                               wampcc::call_info info) {
                              caller.result(info.request_id,
                                            info.args.args_list,
                                            info.args.args_dict);
                            });

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  wamp_args call_args;
  call_args.args_list = json_array({"hello from basic_caller"}, {});

  result_info result = sync_rpc_all(session, "echo", call_args,
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
  unique_ptr<kernel> the_kernel(new kernel(/*{}, logger::console()*/));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  result_info result = sync_rpc_all(session, "xxNOTFOUNDxx", {},
                                    rpc_result_expect::fail);

  if (result.error_uri != WAMP_ERROR_NO_SUCH_PROCEDURE)
    throw runtime_error("actual error_uri doesn't match expected");

  session->close().wait();
}


auto all_tests = [](int port, internal_server& server)
{
  test_rpc(port, server);
  test_call_non_existing_rpc(port, server);
};

TEST_CASE("test_all_salted")
{
  internal_server iserver;
  iserver.enable_salting();
  int port = iserver.start(global_port++);

  all_tests(port, iserver);
}

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

TEST_CASE("test_unsubscribe")
{
  internal_server iserver;
  int port = iserver.start(global_port++);

  unique_ptr<kernel> the_kernel(new kernel(/*{}, logger::console()*/));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  std::promise<t_subscription_id> subscribed;
  bool subscribed_okay = false;

  session->subscribe("uri", {},
                     [&](wampcc::wamp_session&, wampcc::subscribed_info info){
                       subscribed_okay = !info.was_error;
                       subscribed.set_value(info.subscription_id);
                     },
                     [](wampcc::wamp_session&, wampcc::event_info ev){
                     });

  auto fut = subscribed.get_future();
  fut.wait();
  auto subid = fut.get();
  REQUIRE(subscribed_okay==true);

  // test an unsubscribe that should fail
  {
    std::promise<bool> unsubscribed;

    session->unsubscribe(99999,
                         [&](wampcc::wamp_session&, wampcc::unsubscribed_info info) {
                           unsubscribed.set_value(!info.was_error);
                         });

    auto fut2 = unsubscribed.get_future();
    fut2.wait();
    bool unsubscribed_okay = fut2.get();
    REQUIRE(unsubscribed_okay==false);
  }

  // test an unsubscribe that should succeed
  {
    std::promise<bool> unsubscribed;

    session->unsubscribe(subid,
                         [&](wampcc::wamp_session&, wampcc::unsubscribed_info info) {
                           unsubscribed.set_value(!info.was_error);
                         });

    auto fut2 = unsubscribed.get_future();
    fut2.wait();
    bool unsubscribed_okay = fut2.get();
    REQUIRE(unsubscribed_okay==true);
  }

  session->close().wait();
}


int main(int argc, char** argv)
{
  try
  {
    global_port = 27000;

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

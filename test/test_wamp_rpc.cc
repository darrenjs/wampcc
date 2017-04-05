/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;




void test_fast_close_after_normal_close_and_wait(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    session->close();
    session->closed_future().wait();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}



void test_rpc(int port, internal_server& server)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  server.router()->provide("default_realm", "greeting", {},
                           [](wampcc::wamp_invocation& invocation) {
                             invocation.yield({"hello"});
                           });
  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::stdout()));
    auto session = establish_session(the_kernel, port);

    if (!session)
      throw std::runtime_error("fail");

    wampcc::client_credentials credentials;
    credentials.realm  = "default_realm";
    credentials.authid = "peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn =  [=]() -> std::string { return "secret2"; };
    session->initiate_hello(credentials);
    callback_status = e_callback_not_invoked;

    sleep(1);

    if (callback_status != e_open_callback_with_sp)
      throw std::runtime_error("fail");

    std::promise<void> on_reply;
    std::future<void> fut = on_reply.get_future();
    wamp_args call_args;
    call_args.args_list = json_array({"hello from basic_caller"});
     session->call("greeting", {}, call_args,
                   [&on_reply](wamp_call_result result) {
                     try {
                       on_reply.set_value();
                     } catch (...) { /* ignore promise already set error */}
                   });

     auto fut_status = fut.wait_for(std::chrono::milliseconds(200));
     if (fut_status != std::future_status::ready)
       throw runtime_error("timeout waiting for RPC reply");
       cout << "got reply\n";

     session->close().wait();
  }
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

      // for (int j=0; j < 100; j++)
      //   all_tests(port);
    }

    // use one internal_server per test
    for (int i = 0; i < 1000; i++)
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

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

void test_WS_destroyed_after_kernel(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  // Store a wamp_session resource outside of the kernel scope, so that we can
  // have a wamp_session that outlives the kernel.
  shared_ptr<wamp_session> ws_outer;

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));

    auto fut = sock->connect("127.0.0.1", port);

    auto connect_status = fut.wait_for(chrono::milliseconds(1000));
    if (connect_status == future_status::timeout)
    {
      cout << "expected -- should have connected\n";
      return;
    }

    /* attempt to create a session */
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});

    ws_outer = session;
  }

  ws_outer.reset();

  // In this test, the kernel is deleted before the wamp_session is deleted (due
  // to the outer shared_ptr holding on to it). The test below is to determine
  // if the wamp_session close-callback was triggered.  As of 30/11/16, the
  // design is that is wont be called back, because as the tcp_socket is force
  // closes during kernel unwind, that in itself does not cause a callback into
  // the wamp_session to say the session is closed.
  REQUIRE(callback_status == callback_status_t::not_invoked);
}

TEST_CASE("test_WS_destroyed_after_kernel_shared")
{
  // share a common internal_server
  for (int i = 0; i < 5; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);

    for (int j=0; j < global_loops; j++) {
      test_WS_destroyed_after_kernel(port);
    }
  }
}

TEST_CASE("test_WS_destroyed_after_kernel")
{
  // use one internal_server per test
  for (int i = 0; i < global_loops; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);
    test_WS_destroyed_after_kernel(port);
  }
}

int main(int argc, char** argv)
{
  try
  {
    global_port = 20000;

    if (argc>1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);
    return (result < 0xFF ? result : 0xFF);
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

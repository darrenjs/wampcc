/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;

// logging control
// #ifdef TLOG
// #undef TLOG
// #define TLOG(X)
// #endif

void test_WS_destroyed_after_kernel(int port)
{
  TLOG("----- "<< __FUNCTION__<<" -----");

  callback_status = e_callback_not_invoked;

  // Store a wamp_session resource outside of the kernel scope, so that we can
  // have a wamp_session that outlives the kernel.
  shared_ptr<wamp_session> ws_outer;

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    TLOG("attemping socket connection ...");
    auto fut = sock->connect("127.0.0.1", port);

    auto connect_status = fut.wait_for(chrono::milliseconds(1000));
    if (connect_status == future_status::timeout)
    {
      cout << "expected -- should have connected\n";
      return;
    }

    /* attempt to create a session */
    TLOG("attemping session creation");
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});

    TLOG("got session #" << session->unique_id());

    ws_outer = session;

    TLOG("exiting scope (will trigger kernel, io_loop, ev_loop destruction)");

  }

  TLOG("** scope complete");


  TLOG("triggering ~wamp_session...");
  ws_outer.reset();

  // In this test, the kernel is deleted before the wamp_session is deleted (due
  // to the outer shared_ptr holding on to it). The test below is to determine
  // if the wamp_session close-callback was triggered.  As of 30/11/16, the
  // design is that is wont be called back, because as the tcp_socket is force
  // closes during kernel unwind, that in itself does not cause a callback into
  // the wamp_session to say the session is closed.
  assert(callback_status == e_callback_not_invoked);

  TLOG("test success");
}


int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 20000;
    int loops = 500;

    if (argc>1)
      starting_port_number = atoi(argv[1]);


    // share a common internal_server
    for (int i = 0; i < loops; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);

      for (int j=0; j < 100; j++) {
        test_WS_destroyed_after_kernel(port);
      }
    }

    // use one internal_server per test
    for (int i = 0; i < loops; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      test_WS_destroyed_after_kernel(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;

#ifdef TLOG
#undef TLOG
#define TLOG(X)
#endif

void test_WS_destroyed_after_kernel(int port)
{
  TLOG("----- test_WS_destroyed_after_kernel -----");

  callback_status = callback_status_t::not_invoked;

  shared_ptr<wamp_session> ws_outer;
  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    TLOG("attemping socket connection ...");
    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    auto fut = sock->connect("127.0.0.1", port);
    auto connect_status = fut.wait_for(chrono::milliseconds(100));

    if (connect_status == future_status::timeout)
    {
      throw runtime_error("unexpected -- should have connected");
    }
    TLOG("got socket connection");

    /* attempt to create a session */
    TLOG("attemping session creation");
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});
    TLOG("got session");

    TLOG("assigning session to outer scope (causes wamp_session destruction after kernel destruction)");
    ws_outer = session;
    TLOG("exiting scope (will trigger kernel, io_loop, ev_loop destruction)");
  }
  TLOG("scope complete");
  TLOG("triggering ~wamp_session...");
  ws_outer.reset();
  TLOG("complete");

  // In this test, the kernel is deleted before the wamp_session is deleted (due
  // to the outer shared_ptr holding on to it). This ordering means that the
  // wamp_session is still available during the wamp_session callback.
  assert(callback_status == callback_status_t::close_with_sp);

  TLOG("test success");
}


int main(int argc, char** argv)
{
  try
  {
    throw std::runtime_error("TEST STILL UNDER DEVELOPMENT");

    int starting_port_number = 24000;
    int loops = 500;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    // share a common internal_server
    for (int i = 0; i < loops; i++)
    {
      // build a client
      std::unique_ptr<internal_server> iserver(new internal_server());
      iserver->start(starting_port_number++);

      // add connections
      //add_client_connections(port, 10);

      // drop the client
      iserver.reset();

    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

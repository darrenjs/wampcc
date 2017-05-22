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
int global_loops = 100;

void test_WS_destroyed_before_kernel(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));

    /* attempt to connect the socket */
    cout << "attemping socket connection ...\n";
    auto fut = sock->connect("127.0.0.1", port);

    auto connect_status = fut.wait_for(chrono::milliseconds(100));
    if (connect_status == future_status::timeout)
    {
      cout << "    failed to connect\n";
      return;
    }
    cout << "    got socket connection\n";

    /* attempt to create a session */
    cout << "attemping session creation ...\n";
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});

    cout << "    got session\n";

    cout << "calling: session->close().wait()\n";
    session->close().wait();
    cout << "trigger ~wamp_session for " << session->unique_id() << "\n";
    session.reset();
    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";

  }

  // ensure callback was invoked
  assert(callback_status == callback_status_t::close_with_sp);

  cout << "test success\n";
}

TEST_CASE("test_WS_destroyed_before_kernel_shared_server")
{
  // share a common internal_server
  for (int i = 0; i < 10; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);

    for (int j=0; j < global_loops; j++) {
      test_WS_destroyed_before_kernel(port);
    }
  }
}

TEST_CASE("test_WS_destroyed_before_kernel_common_server")
{
  // use one internal_server per test
  for (int i = 0; i < global_loops; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);
    test_WS_destroyed_before_kernel(port);
  }
}

int main(int argc, char** argv)
{
  try
  {
    global_port = 21000;

    if (argc > 1)
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

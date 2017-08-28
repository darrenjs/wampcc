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

void test_WS_destroyed_on_ev_thread(int port)
{
  TSTART();

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    std::unique_ptr<wampcc::tcp_socket> sock( new tcp_socket(the_kernel.get()) );

    auto fut = sock->connect("127.0.0.1", port);

    auto connect_status =fut.wait_for(chrono::milliseconds(100));

    if (connect_status == future_status::timeout)
      throw runtime_error("unexpected -- should have connected");

    /* attempt to create a session */
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      nullptr, {});

    the_kernel->get_event_loop()->dispatch(std::chrono::milliseconds(1000*60),
                                           [session]()
                                           {
                                             cout << "this delayed event should never get called";
                                             return std::chrono::milliseconds(0);
                                           } );
    session.reset();
  }
}

TEST_CASE("test_WS_destroyed_on_ev_thread_shared_server")
{
  // share a common internal_server
  for (int i = 0; i < 5; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);

    for (int j=0; j < global_loops; j++) {
      test_WS_destroyed_on_ev_thread(port);
    }
  }
}

TEST_CASE("test_WS_destroyed_on_ev_thread_dedicated_server")
{
  // use one internal_server per test
  for (int i = 0; i < global_loops; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);
    test_WS_destroyed_on_ev_thread(port);
  }
}

int main(int argc, char** argv)
{
  try
  {
    global_port = 22000;

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

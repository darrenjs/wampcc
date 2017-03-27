/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

#include "wampcc/tcp_socket.h"

#include <stdexcept>

using namespace wampcc;
using namespace std;


void test_close_of_connected_socket(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";
  kernel the_kernel;

  {
    std::unique_ptr<tcp_socket> sock = tcp_connect(the_kernel, port);

    bool cb_invoked = false;
    bool cb_will_be_invoked = sock->close([&]() { cb_invoked = true; });

    // the close request will complete asynchronously, so need to wait for that
    // to happen
    if (cb_will_be_invoked)
      sock->closed_future().wait();

    assert(cb_will_be_invoked == cb_invoked);
  }
}


void test_close_of_unconnected_socket(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";
  kernel the_kernel;

  {
    std::unique_ptr<tcp_socket> sock{new tcp_socket(&the_kernel)};

    bool cb_invoked = false;
    bool cb_will_be_invoked = sock->close([&]() { cb_invoked = true; });

    // the close request will complete asynchronously, so need to wait for that
    // to happen
    if (cb_will_be_invoked)
      sock->closed_future().wait();

    assert(cb_will_be_invoked == cb_invoked);
  }
}

void test_close_of_listen_socket(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";
  kernel the_kernel;

  {
    unique_ptr<tcp_socket> sock{new tcp_socket(&the_kernel)};

    auth_provider server_auth;

    future<uverr> fut =
      sock->listen("", to_string(port), [](unique_ptr<tcp_socket>&, uverr) {});
    future_status status = fut.wait_for(chrono::milliseconds(100));
    if (status == future_status::timeout)
      throw runtime_error("timeout during listen");

    wampcc::uverr err = fut.get();
    if (err)
      throw runtime_error(err.message());


    bool cb_invoked = false;
    bool cb_will_be_invoked = sock->close([&]() { cb_invoked = true; });

    // the close request will complete asynchronously, so need to wait for that
    // to happen
    if (cb_will_be_invoked)
      sock->closed_future().wait();

    assert(cb_will_be_invoked == cb_invoked);
  }
}

int main(int argc, char** argv)
{
  try {
    int starting_port_number = 23100;
    if (argc > 1)
      starting_port_number = atoi(argv[1]);

    internal_server iserver;
    int port = iserver.start(starting_port_number++);

    auto all_tests = [](int port) {
      test_close_of_connected_socket(port);
      test_close_of_unconnected_socket(port);
      test_close_of_listen_socket(port + 1);
    };

    all_tests(port);

    // use one internal_server per test
    int loops = 50;
    for (int i = 0; i < loops; i++)
      all_tests(port);

    return 0;
  } catch (exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

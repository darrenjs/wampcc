/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

#include "wampcc/tcp_socket.h"

#include "mini_test.h"

#include <stdexcept>

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 50;

void test_close_of_connected_socket(int port)
{
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

TEST_CASE("test_close_of_connected_socket")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_close_of_connected_socket(port);
}

TEST_CASE("test_close_of_connected_socket_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_close_of_connected_socket(port);
}

void test_close_of_unconnected_socket(int port)
{
  //std::cout << __FUNCTION__ << std::endl;
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
TEST_CASE("test_close_of_unconnected_socket")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_close_of_unconnected_socket(port);
}
TEST_CASE("test_close_of_unconnected_socket_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_close_of_unconnected_socket(port);
}

void test_close_of_listen_socket(int port)
{
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
TEST_CASE("test_close_of_listen_socket")
{
  int port = global_port++;
  test_close_of_listen_socket(port);
}
TEST_CASE("test_close_of_listen_socket_bulk")
{
  int port = global_port++;
  for (int i = 0; i < global_loops; i++)
    test_close_of_listen_socket(port);
}

TEST_CASE("test_all")
{
  auto all_tests = [](int port) {
    test_close_of_connected_socket(port);
    test_close_of_unconnected_socket(port);
    test_close_of_listen_socket(port + 1);
  };

  internal_server iserver;
  int port = iserver.start(global_port++);

  all_tests(port);

  for (int i = 0; i < global_loops; i++)
    all_tests(port);
}

int main(int argc, char** argv)
{
  try {
    global_port = 26000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return (result < 0xFF ? result : 0xFF );
  } catch (exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

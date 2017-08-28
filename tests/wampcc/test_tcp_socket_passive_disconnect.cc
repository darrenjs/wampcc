/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

#include <stdexcept>

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 500;

void test_passive_disconnect(int port)
{
  TSTART();

  socket_listener the_socket_reader;

  internal_server iserver;
  iserver.start(port);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  tcp_socket sock(the_kernel.get());

  auto fut = sock.connect("127.0.0.1", port);

  std::future_status status = fut.wait_for(std::chrono::milliseconds(10));

  if (status != std::future_status::ready) {
    cout << "result not ready ... waiting\n";
    fut.wait();
  }

  fut.get();

  if (sock.is_connected() == false)
    throw runtime_error("expected to be connected");

  the_socket_reader.start_listening(sock);

  iserver.reset_dealer();


  // kernel is reset before the local socket is closed
  the_kernel.reset();
}

TEST_CASE("test_passive_disconnect")
{
  int port = global_port++;
  test_passive_disconnect(port);
}

TEST_CASE("test_passive_disconnect_bulk")
{
  for (int i = 0; i < global_loops; i++) {
    int port = global_port++;
    test_passive_disconnect(port);
  }
}

void test_passive_disconnect_then_client_sock_close(int port)
{
  TSTART();

  socket_listener the_socket_reader;

  internal_server iserver;
  iserver.start(port);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  tcp_socket sock(the_kernel.get());

  auto fut = sock.connect("127.0.0.1", port);

  std::future_status status = fut.wait_for(std::chrono::milliseconds(10));

  if (status != std::future_status::ready) {
    cout << "result not ready ... waiting\n";
    fut.wait();
  }

  fut.get();

  if (sock.is_connected() == false)
    throw runtime_error("expected to be connected");

  the_socket_reader.start_listening(sock);

  iserver.reset_dealer();

  // close socket before kernel is reset
  sock.close();
  sock.closed_future().wait();

  the_kernel.reset();
}

TEST_CASE("test_passive_disconnect_then_client_sock_close")
{
  int port = global_port++;
  test_passive_disconnect_then_client_sock_close(port);
}

TEST_CASE("test_passive_disconnect_then_client_sock_close_bulk")
{
  for (int i = 0; i < global_loops; i++) {
    int port = global_port++;
    test_passive_disconnect_then_client_sock_close(port);
  }
}

int main(int argc, char** argv)
{
  try {
    global_port = 29000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);
    return (result < 0xFF ? result : 0xFF);
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

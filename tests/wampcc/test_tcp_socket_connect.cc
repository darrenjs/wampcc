/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

#include "wampcc/tcp_socket.h"
#include "wampcc/io_loop.h"

#include <stdexcept>

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 500;

void test_unused_socket()
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  tcp_socket sock(the_kernel.get());
}

void test_canonical_connect(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  {
    tcp_socket sock(the_kernel.get());

    auto fut = sock.connect("127.0.0.1", port);

    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready) {
      cout << "result not ready ... waiting\n";
      fut.wait();
    }

    fut.get();

    if (sock.is_connected() == false)
      throw runtime_error("expected to be connected");
  }

  the_kernel.reset();
}


void test_future_and_socket_discarded(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  {
    tcp_socket sock(the_kernel.get());
    auto fut = sock.connect("127.0.0.1", port);
  }

  {
    tcp_socket sock(the_kernel.get());
    sock.connect("127.0.0.1", port);
  }

  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    auto fut = sp->connect("127.0.0.1", port);
  }

  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }


  the_kernel.reset();
}


void test_future_and_socket_discarded_v2(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }
}


void test_connect_and_delete(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  {
    tcp_socket my_socket_1(the_kernel.get());
    my_socket_1.connect("127.0.0.1", port);
    tcp_socket my_socket_2(the_kernel.get());
    my_socket_2.connect("127.0.0.1", port);
    tcp_socket my_socket_3(the_kernel.get());
    my_socket_3.connect("127.0.0.1", port);
  }

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_2(new tcp_socket(the_kernel.get()));
    sp_2->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_3(new tcp_socket(the_kernel.get()));
    sp_3->connect("127.0.0.1", port);
  }
}


void test_connect_read_close(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  socket_listener my_listener;

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port).wait();
    my_listener.start_listening(sp_1);
    sp_1->close();
  }
}


void test_connect_then_io_stop(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  socket_listener my_listener;

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    auto fut = sp_1->connect("127.0.0.1", port);
    fut.wait();
    my_listener.start_listening(sp_1);
    the_kernel->get_io()->sync_stop();

    // deletion of the socket will proceed fine, because completion of the IO
    // loop implies all sockets have been closed.
    sp_1.reset();
  }
}


TEST_CASE("test_canonical_connect")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_canonical_connect(port);
}

TEST_CASE("test_canonical_connect_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    test_canonical_connect(port);
}

TEST_CASE("test_connect_then_io_stop")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_connect_then_io_stop(port);
}

TEST_CASE("test_connect_then_io_stop_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    test_connect_then_io_stop(port);
}


TEST_CASE("test_future_and_socket_discarded")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_future_and_socket_discarded(port);
}

TEST_CASE("test_future_and_socket_discarded_bulkd")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    test_future_and_socket_discarded(port);
}

TEST_CASE("test_future_and_socket_discarded_v2")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_future_and_socket_discarded_v2(port);
}

TEST_CASE("test_future_and_socket_discarded_v2_bulks")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    test_future_and_socket_discarded_v2(port);
}

TEST_CASE("test_connect_and_delete")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_connect_and_delete(port);
}

TEST_CASE("test_connect_and_delete_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    test_connect_and_delete(port);
}

auto all_tests = [](int port) {
  test_unused_socket();
  test_canonical_connect(port);
  test_connect_then_io_stop(port);
  test_future_and_socket_discarded(port);
  test_future_and_socket_discarded_v2(port);
  test_connect_and_delete(port);
  test_connect_read_close(port);
};

TEST_CASE("all_tests")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  all_tests(port);
}

TEST_CASE("all_tests_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; ++i)
    all_tests(port);
}

int main(int argc, char** argv)
{
  try {
    global_port = 25000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return (result < 0xFF ? result : 0xFF);
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

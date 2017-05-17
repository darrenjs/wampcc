/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/kernel.h"
#include "wampcc/wamp_session.h"
#include "wampcc/websocket_protocol.h"
#include "wampcc/rawsocket_protocol.h"
#include "wampcc/tcp_socket.h"

#include "mini_test.h"

#include <iostream>

using namespace wampcc;

int global_loops = 100;

/*

  $ telnet 255.255.255.255 55555
  Trying 255.255.255.255...
  telnet: Unable to connect to remote host: Network is unreachable

 */
void unreachable_network()
{
  kernel the_kernel({}, logger::nolog());

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut =
      sock->connect("255.255.255.255", /* IP selected to be unreachable */
                    55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(200));

  REQUIRE(completed == std::future_status::ready);

  if (completed == std::future_status::ready) {
    REQUIRE(sock->is_connected() == false);
    sock->close();
  }
}

TEST_CASE("unreachable_network")
{
  for (int i = 0; i < global_loops; i++)
    unreachable_network();
}

void invalid_address()
{
  kernel the_kernel({}, logger::nolog());

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut = sock->connect("0.42.42.42", /* Invalid argument */
                           55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(50));

  REQUIRE(completed == std::future_status::ready);

  if (completed == std::future_status::ready) {
    REQUIRE(sock->is_connected() == false);
    sock->close();
  }
}

TEST_CASE("invalid_address")
{
  for (int i = 0; i < global_loops; i++)
    invalid_address();
}

/*
 Attempting to connect to 10.0.0.0 55555 will normally just hang
 */
void timeout_for_unreachable_connect()
{
  kernel the_kernel({}, logger::nolog());

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut = sock->connect("10.0.0.0", 55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(50));

  REQUIRE(completed == std::future_status::timeout);

  if (completed == std::future_status::timeout) {
    sock->close();
  }
}

TEST_CASE("timeout_for_unreachable_connect")
{
  for (int i = 0; i < global_loops; i++)
    timeout_for_unreachable_connect();
}

/* Note, these tests will only succeed if the system has access to a network. */

int main(int argc, char** argv)
{
  try {
    int result = minitest::run(argc, argv);
    return (result < 0xFF ? result : 0xFF);
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

#include "XXX/kernel.h"
#include "XXX/wamp_session.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"
#include "XXX/tcp_socket.h"

#include <iostream>

using namespace XXX;

enum test_outcome
{
  e_expected,
  e_unexpected
};

/*

  $ telnet 255.255.255.255 55555
  Trying 255.255.255.255...
  telnet: Unable to connect to remote host: Network is unreachable

 */
test_outcome unreachable_network()
{
  kernel the_kernel( {}, logger::nolog() );

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut = sock->connect("255.255.255.255", /* IP selected to be unreachable */
                               55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(200));

  if (completed == std::future_status::ready)
  {
    if (sock->is_connected())
      return e_unexpected;

    // otherwise, close the socket
    sock->close();
    return e_expected;
  }

  return e_unexpected;
}



test_outcome invalid_address()
{
  kernel the_kernel( {}, logger::nolog() );

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut = sock->connect("0.42.42.42", /* Invalid argument */
                               55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(50));

  if (completed == std::future_status::ready)
  {
    if (sock->is_connected())
      return e_unexpected;

    // otherwise, close the socket
    sock->close();
    return e_expected;
  }

  return e_unexpected;
}


/*
 Attempting to connect to 10.0.0.0 55555 will normally just hang
 */
test_outcome timeout_for_unreachable_connect()
{
  kernel the_kernel( {}, logger::nolog() );

  std::unique_ptr<tcp_socket> sock(new tcp_socket(&the_kernel));

  auto fut = sock->connect("10.0.0.0", 55555);

  auto completed = fut.wait_for(std::chrono::milliseconds(50));

  if (completed == std::future_status::timeout)
  {
    sock->close();
    return e_expected ;
  }

  return e_unexpected;
}


#define TEST( X )                                       \
  {                                                     \
  std::cout << "---------- " << #X << " ----------\n";   \
  if ( X () != e_expected)                              \
  {                                                     \
    std::cout << "FAIL for:  " << #X << std::endl;      \
    result = 1;                                        \
  }                                                     \
  }


/* Note, these tests will only succeed if the system has access to a network. */

int main()
{
  int result = 0;
  int loops = 100;

  for (int i =0; i < loops && !result; i++)
    TEST( unreachable_network );

  for (int i =0; i < loops && !result; i++)
    TEST( invalid_address );

  for (int i =0; i < loops && !result; i++)
    TEST( timeout_for_unreachable_connect );


  /* We let any uncaught exceptions (which are not expected) to terminate main,
   * and cause test failure. */
  return result;
}

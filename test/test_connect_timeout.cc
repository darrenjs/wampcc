#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/wamp_session.h"
#include "XXX/wamp_connector.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"

#include <iostream>

using namespace XXX;

enum test_outcome
{
  e_expected,
  e_unexpected
};


test_outcome throw_on_invalid_address()
{
  kernel the_kernel( {}, logger::nolog() );
  the_kernel.start();

  auto wconn = wamp_connector::create(
    &the_kernel,
    "0.42.42.42", /* Invalid argument */
    "55555",
    false,
    [](XXX::session_handle, bool){});

  auto connect_future = wconn->get_future();
  auto connect_status = connect_future.wait_for(std::chrono::milliseconds(50));

  std::shared_ptr<wamp_session> session;

  if (connect_status == std::future_status::ready)
    try
    {
      session = connect_future.get();
    }
    catch (std::exception& e)
    {
      return e_expected;
    }

  return e_unexpected;
}


test_outcome timeout_for_unreachable_connect()
{
  std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::nolog() ) );
  the_kernel->start();

  auto wconn = wamp_connector::create(
    the_kernel.get(),
    "10.255.255.1", "55555",
    false,
    [](XXX::session_handle, bool){});

  auto connect_future = wconn->get_future();

  auto connect_status = connect_future.wait_for(std::chrono::milliseconds(50));

  if (connect_status == std::future_status::timeout)
    return e_expected;

  return e_unexpected;
}


#define TEST( X )                                       \
  if ( X () != e_expected)                              \
  {                                                     \
    std::cout << "FAIL for:  " << #X << std::endl;      \
    result |= 1;                                        \
  }


/* Note, these tests will only succeed if the system has access to a network. */

int main()
{
  int result = 0;

  for (int i =0; i < 20; i++)
  {
    std::cout << "."<< std::flush;
    TEST( throw_on_invalid_address );
    TEST( timeout_for_unreachable_connect );
  }

  /* We let any uncaught exceptions (which are not expected) to terminate main,
   * and cause test failure. */
  return result;
}

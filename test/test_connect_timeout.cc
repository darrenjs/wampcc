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


void on_wamp_connector_completed(std::shared_ptr<wamp_connector> wconn)
{
}


test_outcome throw_on_unreachable_network()
{
  kernel the_kernel( {}, logger::nolog() );

  auto wconn = wamp_connector::create(
    &the_kernel,
    "255.255.255.255", /* IP selected to be unreachable */
    "55555",
    false);

  auto completed = wconn->completion_future().wait_for(std::chrono::milliseconds(50));
  std::shared_ptr<wamp_session> session;

  if (completed == std::future_status::ready)
    try
    {
      session = wconn->create_session( nullptr );
    }
    catch (std::exception& e)
    {
      std::cout << "expected connect error: " << e.what() << std::endl;
      return e_expected;
    }

  return e_unexpected;
}



test_outcome throw_on_invalid_address()
{
  kernel the_kernel( {}, logger::nolog() );

  auto wconn = wamp_connector::create(
    &the_kernel,
    "0.42.42.42", /* Invalid argument */
    "55555",
    false);

  auto completed = wconn->completion_future().wait_for(std::chrono::milliseconds(50));
  std::shared_ptr<wamp_session> session;

  if (completed == std::future_status::ready)
    try
    {
      session = wconn->create_session( nullptr );
    }
    catch (std::exception& e)
    {
      std::cout << "expected connect error: " << e.what() << std::endl;
      return e_expected;
    }

  return e_unexpected;
}




test_outcome timeout_for_unreachable_connect()
{
  std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::nolog() ) );

  auto wconn = wamp_connector::create(
    the_kernel.get(),
    "10.0.0.0", "55555",
    false, on_wamp_connector_completed);

  auto completed = wconn->completion_future().wait_for(std::chrono::milliseconds(50));

  if (completed == std::future_status::timeout)
  {
    return e_expected;
  }

  return e_unexpected;
}



test_outcome cancel_for_unreachable_connect()
{
  std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::nolog() ) );

  auto wconn = wamp_connector::create(
    the_kernel.get(),
    "10.0.0.0", "55555",
    false, on_wamp_connector_completed);

  auto completed = wconn->completion_future().wait_for(std::chrono::milliseconds(50));

  if (completed == std::future_status::timeout)
  {
    bool cancel_worked = wconn->attempt_cancel();
    if (!cancel_worked)
      return e_unexpected;

    wconn->completion_future().wait();

    try
    {
      auto session = wconn->create_session( nullptr );
    }
    catch (std::exception& e)
    {
      return e_expected;
    }

  }

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

  for (int i =0; i < 200; i++)
  {
    TEST( throw_on_unreachable_network );
    TEST( throw_on_invalid_address );
    TEST( timeout_for_unreachable_connect );
    TEST( cancel_for_unreachable_connect );
  }

  /* We let any uncaught exceptions (which are not expected) to terminate main,
   * and cause test failure. */
  return result;
}

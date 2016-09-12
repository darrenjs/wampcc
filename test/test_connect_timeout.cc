
#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/wamp_session.h"
#include "XXX/wamp_connector.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"

#include <iostream>

using namespace XXX;

struct timeout_error : public std::runtime_error
{
  timeout_error()
    : std::runtime_error("timeout_error"){}

};


void make_connection()
{
  auto __logger = logger::stdlog(std::cout,
                                 logger::levels_upto(logger::eError), 0);

  std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, __logger) );
  the_kernel->start();

  std::promise<void> promise_on_close;


  auto wconn = wamp_connector::create(
    the_kernel.get(),
    "10.0.0.0", "55555",
    false,
    [&promise_on_close](XXX::session_handle, bool is_open){
      if (!is_open)
        promise_on_close.set_value();
    }
    );

  auto connect_future = wconn->get_future();
  auto connect_status = connect_future.wait_for(std::chrono::milliseconds(50));

  if (connect_status == std::future_status::timeout)
  {
    throw timeout_error();
  }
  else
  {
    throw std::runtime_error("call should have timed-out");
  }

}


int run_test()
{
  try
  {
    make_connection();
  }
  catch (timeout_error&)
  {
    // OK, this is what we expected
    return 0;
  }

  return 1; // unexpected
}




int main()
{
  try
  {
    for (int i =0; i < 100; i++)
    {
      std::cout << "."<< std::flush;
      run_test();
    }
    return 0;
  }
  catch (std::exception& e)
  {
    std::cerr << "error: " << e.what() << std::endl;
    return 1;
  }
}

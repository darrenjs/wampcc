#ifndef XXX_TEST_COMMON_H
#define XXX_TEST_COMMON_H

#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/wamp_session.h"
#include "XXX/wamp_connector.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"
#include "XXX/dealer_service.h"
#include "XXX/event_loop.h"

#include <iostream>
#include <string.h>


#include <unistd.h>
#undef NDEBUG

#include <assert.h>

#define TLOG( X ) std::cout << X << std::endl

namespace XXX {


enum test_outcome
{
  e_expected,
  e_unexpected
};

class internal_client  // TODO: rename as internal_server
{
public:
  internal_client()
    : m_kernel(new kernel({}, logger::nolog())),
      m_dealer(new dealer_service(*(m_kernel.get()), nullptr ))
  {
  }

  ~internal_client()
  {
    m_dealer.reset();
    m_kernel.reset();
  }

  int start(int starting_port_number)
  {
    auth_provider server_auth;
    server_auth.provider_name = [](const std::string){ return "programdb"; };
    server_auth.permit_user_realm = [](const std::string& /*user*/, const std::string& /*realm*/){ return true; };
    server_auth.get_user_secret   = [](const std::string& /*user*/, const std::string& /*realm*/){ return "secret2";};

    for (int port = starting_port_number; port < 65535; port++)
    {
      std::future<int> fut_listen_err = m_dealer->listen(port, server_auth);
      std::future_status status = fut_listen_err.wait_for(std::chrono::milliseconds(100));
      if (status == std::future_status::ready)
      {
        int err = fut_listen_err.get();
        if (err == 0)
          return port;

      }
    }

    throw std::runtime_error("failed to find an available port number for listen socket");
    return 0;
  }

  void reset_kernel()
  {
    m_kernel.reset();
  }

  void reset_dealer()
  {
    m_dealer.reset();
  }

  kernel* get_kernel() { return m_kernel.get(); }
private:
  std::unique_ptr<kernel>         m_kernel;
  std::shared_ptr<dealer_service> m_dealer;
};


enum
{
  e_callback_not_invoked,
  e_close_callback_with_sp,
  e_close_callback_without_sp
} callback_status;


void session_cb(std::weak_ptr<wamp_session> wp, bool is_open)
{
  if (is_open == false)
  {
    if (auto sp=wp.lock())
      callback_status = e_close_callback_with_sp;
    else
      callback_status = e_close_callback_without_sp;
  }
}



}

#endif
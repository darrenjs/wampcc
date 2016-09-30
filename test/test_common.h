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

namespace XXX {


enum test_outcome
{
  e_expected,
  e_unexpected
};

class internal_client
{
public:
  internal_client()
    : m_kernel(new kernel({}, logger::nolog())),
      m_dealer(new dealer_service(*(m_kernel.get()), nullptr ))
  {
  }

  int start()
  {
    auth_provider server_auth;
    server_auth.provider_name = [](const std::string){ return "programdb"; };
    server_auth.permit_user_realm = [](const std::string& /*user*/, const std::string& /*realm*/){ return true; };
    server_auth.get_user_secret   = [](const std::string& /*user*/, const std::string& /*realm*/){ return "secret2";};

    int port = 20000;
    while (port < 65536)
    {
      std::future<int> fut_listen_err = m_dealer->listen(port, server_auth);
      std::future_status status = fut_listen_err.wait_for(std::chrono::milliseconds(100));
      if (status == std::future_status::ready)
      {
        int err = fut_listen_err.get();
        if (err == 0)
        {
          std::cout << "listening on port: " << port << "\n";
          return port;
        }
      }
    }

    return 0;
  }

private:
  std::unique_ptr<kernel>         m_kernel;
  std::shared_ptr<dealer_service> m_dealer;
};


}

#endif

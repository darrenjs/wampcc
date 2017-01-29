#ifndef XXX_TEST_COMMON_H
#define XXX_TEST_COMMON_H

#include "XXX/kernel.h"
#include "XXX/wamp_session.h"
#include "XXX/tcp_socket.h"
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


struct socket_listener : public io_listener
{
  virtual void io_on_read(char*, ssize_t n)
  {
    std::cout << "socket_listener: io_on_read, n=" << n << std::endl;
  }
};



enum test_outcome
{
  e_expected,
  e_unexpected
};

class internal_server
{
public:
  internal_server()
    : m_kernel(new kernel({}, logger::nolog())),
      m_dealer(new dealer_service(m_kernel.get(), nullptr ))
  {
  }

  ~internal_server()
  {
    m_dealer.reset();
    m_kernel.reset();
  }

  int start(int starting_port_number)
  {
    auth_provider server_auth;
    server_auth.provider_name = [](const std::string){ return "programdb"; };
    server_auth.permit_user_realm = [](const std::string& /*user*/,
                                       const std::string& /*realm*/){
      std::set<std::string> methods {"wampcra"};
      return std::make_tuple(auth_provider::e_authenticate, std::move(methods));
    };
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


std::shared_ptr<wamp_session> establish_session(std::unique_ptr<kernel> & the_kernel, int port)
{
  static int count = 0;
  count++;

  std::unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));

  auto fut = sock->connect("127.0.0.1", port);

  auto connect_status = fut.wait_for(std::chrono::milliseconds(100));
  if (connect_status == std::future_status::timeout)
  {
    return std::shared_ptr<wamp_session>();
  }

  /* attempt to create a session */
  std::shared_ptr<wamp_session> session;
  if (count % 2)
    session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});
  else
    session = wamp_session::create<websocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});

  return session;
}

}

#endif

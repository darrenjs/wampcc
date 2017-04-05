#ifndef WAMPCC_TEST_COMMON_H
#define WAMPCC_TEST_COMMON_H

#include "wampcc/kernel.h"
#include "wampcc/wamp_session.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/websocket_protocol.h"
#include "wampcc/rawsocket_protocol.h"
#include "wampcc/wamp_router.h"
#include "wampcc/event_loop.h"

#include <iostream>
#include <chrono>
#include <string.h>


#include <unistd.h>
#undef NDEBUG

#include <assert.h>

#define TLOG(X) std::cout << X << std::endl

#define TSTART() std::cout << "==== " << __FUNCTION__ << std::endl

namespace wampcc
{


struct socket_listener
{
  void io_on_read(char*, size_t n)
  {
    std::cout << "socket_listener: io_on_read, n=" << n << std::endl;
  }

  void io_on_error(uverr ec)
  {
    std::cout << "socket_listener: io_on_error, err=" << ec << std::endl;
  }

  void start_listening(std::shared_ptr<tcp_socket> sock)
  {
    sock->start_read([this](char* s, size_t n) { this->io_on_read(s, n); },
                     [this](uverr e) { this->io_on_error(e); });
  }

  void start_listening(tcp_socket& sock)
  {
    sock.start_read([this](char* s, size_t n) { this->io_on_read(s, n); },
                    [this](uverr e) { this->io_on_error(e); });
  }
};

enum test_outcome { e_expected, e_unexpected };

class internal_server
{
public:
  internal_server()
    : m_kernel(new kernel({}, logger::nolog())),
      m_route(new wamp_router(m_kernel.get(), nullptr))
  {
  }

  ~internal_server()
  {
    m_router.reset();
    m_kernel.reset();
  }

  int start(int starting_port_number)
  {
    auth_provider server_auth;
    server_auth.provider_name = [](const std::string) { return "programdb"; };
    server_auth.policy =
        [](const std::string& /*user*/, const std::string& /*realm*/) {
      std::set<std::string> methods{"wampcra"};
      return std::make_tuple(auth_provider::mode::authenticate,
                             std::move(methods));
    };
    server_auth.user_secret =
        [](const std::string& /*user*/,
           const std::string& /*realm*/) { return "secret2"; };

    for (int port = starting_port_number; port < 65535; port++) {
      std::future<uverr> fut_listen_err = m_router->listen(std::string("127.0.0.1"), std::to_string(port), server_auth);
      std::future_status status =
          fut_listen_err.wait_for(std::chrono::milliseconds(100));
      if (status == std::future_status::ready) {
        wampcc::uverr err = fut_listen_err.get();
        if (err == 0)
          return port;
      }
    }

    throw std::runtime_error(
        "failed to find an available port number for listen socket");
    return 0;
  }

  void reset_kernel() { m_kernel.reset(); }

  void reset_dealer() { m_router.reset(); }

  kernel* get_kernel() { return m_kernel.get(); }

  wamp_router* router() { return m_router.get(); }

private:
  std::unique_ptr<kernel> m_kernel;
  std::shared_ptr<wamp_router> m_router;
};


enum {
  e_callback_not_invoked,
  e_close_callback_with_sp,
  e_close_callback_without_sp,
  e_open_callback_with_sp,
  e_open_callback_without_sp
} callback_status;


void session_cb(std::weak_ptr<wamp_session> wp, bool is_open)
{
  if (is_open == false) {
    if (auto sp = wp.lock())
      callback_status = e_close_callback_with_sp;
    else
      callback_status = e_close_callback_without_sp;
  }
  else
  {
    if (auto sp = wp.lock())
      callback_status = e_open_callback_with_sp;
    else
      callback_status = e_open_callback_without_sp;
  }
}


std::unique_ptr<tcp_socket> tcp_connect(kernel& k, int port)
{
  std::unique_ptr<tcp_socket> sock{new tcp_socket(&k)};

  auto fut = sock->connect("127.0.0.1", port);
  auto status = fut.wait_for(std::chrono::milliseconds(100));

  if (status == std::future_status::timeout)
    throw std::runtime_error("timeout during connect");

  auto err = fut.get();
  if (err)
    throw std::runtime_error(err.message());

  if (sock->is_connected() == false)
    throw std::runtime_error("expected to be connected");

  return sock;
}

std::shared_ptr<wamp_session> establish_session(
    std::unique_ptr<kernel>& the_kernel, int port)
{
  static int count = 0;
  count++;

  std::unique_ptr<tcp_socket> sock(new tcp_socket(the_kernel.get()));

  auto fut = sock->connect("127.0.0.1", port);

  auto connect_status = fut.wait_for(std::chrono::milliseconds(100));
  if (connect_status == std::future_status::timeout) {
    return std::shared_ptr<wamp_session>();
  }

  /* attempt to create a session */
  std::shared_ptr<wamp_session> session;
  if (count % 2)
    session = wamp_session::create<rawsocket_protocol>(
        the_kernel.get(), std::move(sock), session_cb, {});
  else
    session = wamp_session::create<websocket_protocol>(
        the_kernel.get(), std::move(sock), session_cb, {});

  return session;
}
}

#endif

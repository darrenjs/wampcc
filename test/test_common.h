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
      m_router(new wamp_router(m_kernel.get(), nullptr))
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


enum class callback_status_t {
  not_invoked,
  close_with_sp,
  close_without_sp,
  open_with_sp,
  open_without_sp
} callback_status;


std::unique_ptr< std::promise<callback_status_t> > sessioncb_promise;
std::future<callback_status_t> reset_callback_result()
{
  sessioncb_promise.reset( new std::promise<callback_status_t>());
  return sessioncb_promise->get_future();
}




void session_cb(std::weak_ptr<wamp_session> wp, bool is_open)
{
  if (is_open == false) {
    if (auto sp = wp.lock())
      callback_status = callback_status_t::close_with_sp;
    else
      callback_status = callback_status_t::close_without_sp;
  }
  else
  {
    if (auto sp = wp.lock())
      callback_status = callback_status_t::open_with_sp;
    else
      callback_status = callback_status_t::open_without_sp;
  }

  if (sessioncb_promise)
    sessioncb_promise->set_value(callback_status);
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


void perform_realm_logon(std::shared_ptr<wamp_session>&session,
                         std::string realm="default_realm")
{
  if (!session)
    throw std::runtime_error("perform_realm_logon: null session");

  auto fut = reset_callback_result();

  wampcc::client_credentials credentials;
  credentials.realm  = realm;
  credentials.authid = "peter";
  credentials.authmethods = {"wampcra"};
  credentials.secret_fn =  [=]() -> std::string { return "secret2"; };

  session->initiate_hello(credentials);

  auto long_time = std::chrono::milliseconds(200);

  if (fut.wait_for(long_time) != std::future_status::ready)
    throw std::runtime_error("timeout waiting for realm logon");

  if (fut.get() != callback_status_t::open_with_sp)
    throw std::runtime_error("realm logon failed");
}


enum class rpc_result_expect {nocheck, success, fail };
wamp_call_result sync_rpc_all(std::shared_ptr<wamp_session>&session,
                              const char* rpc_name,
                              wamp_args call_args,
                              rpc_result_expect expect)
{
  if (!session)
    throw std::runtime_error("sync_rpc_all: null session");

  std::promise<wamp_call_result> result_prom;
  std::future<wamp_call_result> result_fut = result_prom.get_future();
  session->call(rpc_name, {}, call_args,
                [&result_prom](wamp_call_result r) {
                  result_prom.set_value(r);
                });

  auto long_time = std::chrono::milliseconds(200);

  if (result_fut.wait_for(long_time) != std::future_status::ready)
    throw std::runtime_error("timeout waiting for RPC reply");

  wamp_call_result result = result_fut.get();

  if (expect==rpc_result_expect::success && result.was_error==true)
    throw std::runtime_error("expected call to succeed");

  if (expect==rpc_result_expect::fail && result.was_error==false)
    throw std::runtime_error("expected call to fail");

  return result;
}


}

#endif

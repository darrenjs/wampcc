/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wamp_router.h"

#include "wampcc/kernel.h"
#include "wampcc/rpc_man.h"
#include "wampcc/pubsub_man.h"
#include "wampcc/event_loop.h"
#include "wampcc/io_loop.h"
#include "wampcc/ssl_socket.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/log_macros.h"
#include "wampcc/protocol.h"

#include <string.h>

namespace wampcc
{

wamp_router::wamp_router(kernel* __svc, on_rpc_registered cb)
  : m_kernel(__svc),
    __logger(__svc->get_logger()),
    m_rpcman(new rpc_man(
        __svc, [this](const rpc_details& r) { this->rpc_registered_cb(r); })),
    m_pubsub(new pubsub_man(__svc)),
    m_on_rpc_registered(cb){};


wamp_router::~wamp_router()
{
  // TODO: need to detect if dealer is going to try to delete the wamp_session
  // on the EV thread -- not able to perform the wait here in such cases.

  /* First we shutdown the server sockets, so that we dont have IO callbacks
   * entering into self as the destructor is underway. */
  decltype(m_server_sockets) server_socks;
  {
    std::lock_guard<std::mutex> guard(m_server_sockets_lock);
    server_socks.swap(m_server_sockets);
  }
  for (auto& sock : server_socks)
    sock->close();
  for (auto& sock : server_socks)
    sock->closed_future().wait();
  server_socks.clear();

  /* Next close our wamp_sessions */
  std::map<t_sid, std::shared_ptr<wamp_session>> sessions;
  {
    std::lock_guard<std::mutex> guard(m_sessions_lock);
    m_sessions.swap(sessions);
  }
  for (auto& item : sessions)
    item.second->close();
  for (auto& item : sessions)
    item.second->closed_future().wait();
  sessions.clear();

  std::lock_guard<std::recursive_mutex> guard(m_lock);
  m_on_rpc_registered = nullptr;
}


std::future<uverr> wamp_router::listen(const std::string& node,
                                       const std::string& service,
                                       auth_provider auth,
                                       tcp_socket::addr_family af)
{
  return listen(std::move(auth),
                {false, wampcc::all_protocols, wampcc::all_serialisers,
                 node, service, af});
}


std::future<uverr> wamp_router::listen(auth_provider auth, int p)
{
  return listen(std::move(auth),
                {false, wampcc::all_protocols, wampcc::all_serialisers,
                 "", std::to_string(p),
                 tcp_socket::addr_family::inet4});
}


void wamp_router::provide(const std::string& realm, const std::string& uri,
                          const json_object& options, rpc_cb user_cb,
                          void* user_data)
{
  // TODO: dispatch this on the event thread?
  m_rpcman->register_internal_rpc_2(realm, uri, options, user_cb, user_data);
}


void wamp_router::publish(const std::string& realm, const std::string& topic,
                          const json_object& options, wamp_args args)
{
  /* USER thread */

  std::weak_ptr<wamp_router> wp = this->shared_from_this();

  // TODO: how to use bind here, to pass options in as a move operation?
  m_kernel->get_event_loop()->dispatch([wp, topic, realm, args, options]() {
    if (auto sp = wp.lock())
      sp->m_pubsub->inbound_publish(realm, topic, options, args);
  });
}


void wamp_router::rpc_registered_cb(const rpc_details& r)
{
  std::lock_guard<std::recursive_mutex> guard(m_lock);
  if (m_on_rpc_registered)
    m_on_rpc_registered(r.uri);
}


void wamp_router::handle_inbound_call(
    wamp_session* sptr, // TODO: possibly change this to a shared_ptr
    const std::string& uri, wamp_args args, wamp_invocation_reply_fn fn)
{
  /* EV thread */

  // TODO: use direct lookup here, instead of that call to public function,
  // wheich can then be deprecated
  try {
    rpc_details rpc = m_rpcman->get_rpc_details(uri, sptr->realm());
    if (rpc.registration_id) {
      if (rpc.type == rpc_details::eInternal) {
        /* CALL request is for an internal procedure */

        if (rpc.user_cb) {
          wamp_invocation invoke;
          invoke.user = rpc.user_data;
          invoke.args = std::move(args);

          invoke.yield_fn = [fn](json_array arg_list, json_object arg_dict) {
            wamp_args args{std::move(arg_list), std::move(arg_dict)};
            if (fn)
              fn(args, std::unique_ptr<std::string>());
          };

          invoke.error_fn = [fn](std::string error_uri, json_array arg_list,
                                 json_object arg_dict) {
            wamp_args args{std::move(arg_list), std::move(arg_dict)};
            if (fn)
              fn(args,
                 std::unique_ptr<std::string>(new std::string(error_uri)));
          };

          rpc.user_cb(invoke);

        } else
          throw wamp_error(WAMP_ERROR_NO_ELIGIBLE_CALLEE);

      } else {
        /* CALL request is for an external RPC */
        if (auto sp = rpc.session.lock())
          sp->invocation(rpc.registration_id, json_object(), args, fn);
        else
          throw wamp_error(WAMP_ERROR_NO_ELIGIBLE_CALLEE);
      }
    } else {
      /* RPC uri lookup failed */
      throw wamp_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
    }
  } catch (wampcc::wamp_error& ex) {
    if (fn)
      fn(ex.args(), std::unique_ptr<std::string>(new std::string(ex.what())));
  } catch (std::exception& ex) {
    if (fn)
      fn(wamp_args(), std::unique_ptr<std::string>(new std::string(ex.what())));
  } catch (...) {
    if (fn)
      fn(wamp_args(),
         std::unique_ptr<std::string>(new std::string(WAMP_RUNTIME_ERROR)));
  }
}


void wamp_router::handle_session_state_change(std::weak_ptr<wamp_session> wp,
                                              bool is_open)
{
  /* EV thread */
  if (auto session = wp.lock()) {
    if (!is_open) {
      m_rpcman->session_closed(session);
      m_pubsub->session_closed(session);

      std::lock_guard<std::mutex> guard(m_sessions_lock);
      m_sessions.erase(session->unique_id());
    }
  }
}

// std::future<void> wamp_router::close()
// {
//   // ANY thread

//   {
//     std::lock_guard<std::mutex> guard(m_sesions_lock);
//     for (auto & item : m_sessions)
//     {
//       std::cout << "wamp_router closing session \n";
//       item.second->close();
//       std::cout << "wamp_router closing session ... done \n";
//     }
//   }

//   for (auto & socket : m_server_sockets)
//   {
//     socket->close();
//   }

//   // TODO: next, need to remove all listen sockets we have
//   std::cout << "wamp_router returning future\n";
//   return m_promise_on_close.get_future();
// }

void wamp_router::check_has_closed()
{
  // TODO: perform state check to see if all resources this class is responsible
  // for have closed, in which case we can set the close promise

  size_t num_sessions;
  {
    std::lock_guard<std::mutex> guard(m_sessions_lock);
    num_sessions = m_sessions.size();
  }

  if (num_sessions == 0)
    m_promise_on_close.set_value();
}

std::future<uverr> wamp_router::listen(auth_provider auth,
                                       const listen_options& listen_opts)
{
  if (listen_opts.ssl && m_kernel->get_ssl() == nullptr)
    throw std::runtime_error("wampcc kernel SSL context is null; can't use SSL");

  auto on_new_client = [this, auth, listen_opts](std::unique_ptr<tcp_socket> sock) {
    /* IO thread */

    /* This lambda is invoked the when a socket has been accepted. */

    server_msg_handler handlers;

    handlers.on_call = [this](wamp_session* s, std::string u,
                                   wamp_args args, wamp_invocation_reply_fn f) {
      this->handle_inbound_call(s, u, std::move(args), f);
    };

    handlers.on_publish =
        [this](wamp_session* sptr, std::string uri, json_object options,
               wamp_args args) {
      // TODO: break this out into a separte method, and handle error
      m_pubsub->inbound_publish(sptr->realm(), uri, std::move(options),
                                std::move(args));
    };

    handlers.on_subscribe =
        [this](wamp_session* p, t_request_id request_id, std::string uri,
               json_object& options) {
      return this->m_pubsub->subscribe(p, request_id, uri, options);
    };

    handlers.on_unsubscribe = [this](
        wamp_session* p, t_request_id request_id, t_subscription_id sub_id) {
      this->m_pubsub->unsubscribe(p, request_id, sub_id);
    };

    handlers.on_register = [this](wamp_session* ses,
                                  t_request_id request_id,
                                  json_object& options,
                                  std::string& uri) -> void {
      auto registration_id = m_rpcman->handle_inbound_register(ses, uri);
      ses->registered(request_id, registration_id);
    };

    auto fd = sock->fd_info().second;

    protocol_builder_fn builder_fn = [this, listen_opts](tcp_socket* sock,
                                                         protocol::t_msg_cb _msg_cb,
                                                         protocol::protocol_callbacks cb) {
      selector_protocol::options selector_opts;
      selector_opts.protocols = listen_opts.protocols;
      selector_opts.serialisers = listen_opts.serialisers;
      std::unique_ptr<protocol> up(
        new selector_protocol(m_kernel, sock, _msg_cb, cb, selector_opts));
      return up;
    };

    std::shared_ptr<wamp_session> sp =
        wamp_session::create(m_kernel, std::move(sock),
                             [this](std::weak_ptr<wamp_session> s, bool b) {
                               this->handle_session_state_change(s, b);
                             },
                             builder_fn, handlers, auth);
    {
      std::lock_guard<std::mutex> guard(m_sessions_lock);
      m_sessions[sp->unique_id()] = sp;

      // test code to drop a connection
      //event_loop::timer_fn fn = [sp](){ sp->close(); return std::chrono::milliseconds(0); };
      //event_loop::timer_fn fn = [sp](){ sp->fast_close(); return std::chrono::milliseconds(0); };
      //event_loop::timer_fn fn = [sp](){ sp->proto_close(); return std::chrono::milliseconds(0); };
      //m_kernel->get_event_loop()->dispatch(std::chrono::milliseconds(5000),fn);
    }

    LOG_INFO("session #" << sp->unique_id() << " created, protocol: "
                         << sp->protocol_name() << ", fd: " << fd);
  };

  /* Create the actual IO server socket */

  std::unique_ptr<tcp_socket> sock(
    listen_opts.ssl? new ssl_socket(m_kernel) : new tcp_socket(m_kernel));

  tcp_socket* ptr = sock.get();

  {
    std::lock_guard<std::mutex> guard(m_server_sockets_lock);
    m_server_sockets.push_back(std::move(sock));
  }

  auto fut = ptr->listen(
      listen_opts.node, listen_opts.service,
      [on_new_client](std::unique_ptr<tcp_socket>& clt, uverr ec) {
        /* IO thread */
        if (!ec)
          on_new_client(std::move(clt));
        else {
          // TODO: need to capture 'this' for this logging line to work, however
          // first need to make sure wamp_router shutdown is controlled.

//          LOG_WARN("accept() failed: " << ec.os_value() << ", "
//                   << e.message());
        }

      },
      listen_opts.af);

  return fut;
}


} // namespace

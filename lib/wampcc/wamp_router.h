/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_WAMP_ROUTER_H
#define WAMPCC_WAMP_ROUTER_H

#include "wampcc/wamp_session.h"
#include "wampcc/error.h"

#include <jalson/jalson.h>

#include <memory>
#include <future>

namespace wampcc {

  class kernel;
  class pubsub_man;
  class rpc_man;
  struct rpc_details;

struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};

class wamp_router : public std::enable_shared_from_this<wamp_router>
{
public:
  wamp_router(kernel *  __svc, dealer_listener*);
  ~wamp_router();

  /** Request asynchronous close */
//  std::future<void> close();

  /* Asynchronously begin accepting connections on the given port. If the bind
   * and or listen fails, a non-zero error code is returned in the future. */
  std::future<uverr> listen(int port,
                            auth_provider auth); // TODO: needs interface argument

  /** Publish to an internal topic */
  void publish(const std::string& realm,
               const std::string& uri,
               const jalson::json_object& options,
               wamp_args args);

  /** Provide an internal RPC */
  void provide(const std::string& realm,
               const std::string& uri,
               const jalson::json_object& options,
               rpc_cb cb,
               void * data = nullptr);

private:

  void rpc_registered_cb(const rpc_details&);
  void handle_inbound_call(wamp_session*,
                           const std::string&,
                           wamp_args args,
                           wamp_invocation_reply_fn);

  void handle_session_state_change(std::weak_ptr<wamp_session>, bool);

  void check_has_closed();

  wamp_router(const wamp_router&) = delete;
  wamp_router& operator=(const wamp_router&) = delete;

  kernel * m_kernel;
  logger & __logger; /* name chosen for log macros */

  std::recursive_mutex m_lock;

  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  std::mutex m_sesions_lock;
  std::map<t_sid, std::shared_ptr<wamp_session> > m_sessions;

  std::promise< void > m_promise_on_close;

  dealer_listener* m_listener;

  std::mutex m_server_sockets_lock;
  std::vector<std::unique_ptr<tcp_socket>> m_server_sockets;
};

} // namespace

#endif

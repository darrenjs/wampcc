/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_WAMP_ROUTER_H
#define WAMPCC_WAMP_ROUTER_H

#include "wampcc/error.h"
#include "wampcc/json.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/wamp_session.h"

#include <memory>
#include <future>

namespace wampcc
{

class kernel;
class pubsub_man;
class rpc_man;
class wamp_router;
struct rpc_details;

/** Callback type invoked when a wamp_router has been provided with a new RPC. **/
typedef std::function<void(const rpc_details&)> on_rpc_registered;

/** Callback type invoked when an RPC is being unregistered from a wamp_router. **/
typedef std::function<void(const rpc_details&)> on_rpc_unregistered;

/** Callback type invoked when the state of a session is changed in a wamp_router.
 *
 *  @todo Is passing wamp_session& to outside safe? Possiblity of deadlock if the outside
 *  function calls wamp_session::uniqueid or authid.
**/
typedef std::function<void(wamp_session&, bool)> on_session_state_change;

/** Aggregate representing the details of a CALL request that has arrived at the
 * router and is to be handled via callback of user code. */
struct call_info
{
  t_request_id request_id;
  json_object options;
  wamp_args args;
  void * user;
};

typedef std::function<void(wamp_router&,
                           wamp_session&,
                           call_info)> on_call_fn;
struct rpc_details
{
  enum { eInternal, eRemote } type;

  uint64_t registration_id; // 0 implies invalid
  std::string uri;
  std::string realm;
  session_handle session;
  json_object options;
  on_call_fn user_cb; // applies only for eInternal
  void* user;         // applies only for eInternal
  rpc_details() : registration_id(0), user(nullptr) {}
};



class wamp_router : public std::enable_shared_from_this<wamp_router>
{
public:

  struct listen_options
  {
    bool ssl;     /* if true, use SSL/TLS socket (wampcc::kernel must also be configured to use SSL) */
    int protocols;  /* mask of protocol_type bits */
    int serialisers;  /* maks of serialiser_type bits */

    // connection details
    std::string node;     // interface addr, or leave blank
    std::string service;  // service or port number
    tcp_socket::addr_family af;

    // socket options
    tcp_socket::options sockopts;

    listen_options()
      : ssl(false),
        protocols(all_protocols),
        serialisers(all_serialisers),
        af(tcp_socket::addr_family::unspec)
    {}

    listen_options(bool ssl_, int protocols_, int serialisers_, std::string node_,
                   std::string svc_, tcp_socket::addr_family af_,
                   tcp_socket::options sockopts_)
      : ssl(ssl_),
        protocols(protocols_),
        serialisers(serialisers_),
        node(node_),
        service(svc_),
        af(af_),
        sockopts(sockopts_)
    {}
  };

  wamp_router(kernel* __svc, on_rpc_registered = nullptr, on_rpc_unregistered = nullptr, on_session_state_change=nullptr);
  ~wamp_router();

  /** Request asynchronous close */
  //  std::future<void> close();

  /** Asynchronously begin accepting connections on given port. If the bind
   * or listen fails, a non-zero error code is returned in the future. */
  std::future<uverr> listen(
      const std::string& node, const std::string& service, auth_provider auth,
      tcp_socket::addr_family = tcp_socket::addr_family::unspec);

  /** Asynchronously accept, on given port, using IPv4 */
  std::future<uverr> listen(auth_provider auth, int port);

  /** Generic listen method. Use this option to enable use of SSL, and to have
   * finer control over which WAMP protocols will be permitted.  */
  std::future<uverr> listen(auth_provider auth, const listen_options&);

  /** Publish to an internal topic */
  void publish(const std::string& realm, const std::string& uri,
               const json_object& options, wamp_args args);

  /** Associate a callback function with a procedure uri.  The callback is
   * called when a CALL request is received for the procedure.  The callback
   * should reply to the caller with a RESULT or ERROR message. */
  t_registration_id callable(const std::string& realm,
                const std::string& uri,
                on_call_fn,
                void * user = nullptr);

  /** Unregister a callable previously added. */
  void unregister_callable(const std::string& realm, t_registration_id id);

  /** Return list of addresses the router is currently listening on. */
  std::vector<socket_address> get_listen_addresses() const;

private:
  void rpc_registered_cb(const rpc_details&);
  void handle_inbound_call(wamp_session*,t_request_id,std::string&,
                           json_object&,wamp_args&);

  void handle_session_state_change(wamp_session&, bool);
  void rpc_unregistered_cb(const rpc_details&);

  void check_has_closed();

  wamp_router(const wamp_router&) = delete;
  wamp_router& operator=(const wamp_router&) = delete;

  kernel* m_kernel;
  logger& __logger; /* name chosen for log macros */

  std::recursive_mutex m_lock;

  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  std::mutex m_sessions_lock;
  std::map<t_session_id, std::shared_ptr<wamp_session>> m_sessions;

  std::promise<void> m_promise_on_close;

  on_rpc_registered m_on_rpc_registered;
  on_rpc_unregistered m_on_rpc_unregistered;
  on_session_state_change m_on_session_state_change;

  mutable std::mutex m_server_sockets_lock;
  std::vector<std::unique_ptr<tcp_socket>> m_server_sockets;
};

} // namespace

#endif

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_RPC_MAN_H
#define WAMPCC_RPC_MAN_H

#include "wampcc/types.h"
#include "wampcc/wamp_session.h"
#include "wampcc/wamp_router.h"
#include "wampcc/json.h"

#include <functional>
#include <map>
#include <string>
#include <mutex>
#include <memory>
#include <list>

namespace wampcc
{

class event_loop;
struct logger;
class kernel;

struct rpc_details
{
  enum { eInternal, eRemote } type;

  uint64_t registration_id; // 0 implies invalid
  std::string uri;
  session_handle session;
  on_call_fn user_cb; // applies only for eInternal
  void* user;         // applies only for eInternal
  rpc_details() : registration_id(0), user(nullptr) {}
};

typedef std::function<void(const rpc_details&)> rpc_added_cb;

class rpc_man
{
public:
  rpc_man(kernel*, rpc_added_cb);

  void handle_inbound_register(wamp_session&, t_request_id, const std::string&);

  void handle_inbound_unregister(wamp_session&, t_request_id,
                                 t_registration_id);

  uint64_t register_internal_rpc(const std::string& realm,
                                 const std::string& uri, on_call_fn,
                                 void* user);

  rpc_details get_rpc_details(const std::string& rpcname,
                              const std::string& realm);

  void session_closed(std::shared_ptr<wamp_session>&);

  json_array get_procedures(const std::string& realm) const;

private:
  rpc_man(const rpc_man&) = delete;
  rpc_man& operator=(const rpc_man&) = delete;

  void register_rpc(session_handle, std::string realm, rpc_details& r);

  logger& __logger; /* name chosen for log macros */
  rpc_added_cb m_rpc_added_cb;

  mutable std::mutex m_rpc_map_lock;

  uint64_t m_next_regid;

  typedef std::map<t_registration_id, std::shared_ptr<rpc_details>>
      map_id_to_rpc;
  typedef std::map<std::string, std::shared_ptr<rpc_details>> map_uri_to_rpc;

  // map from realm to rpc-by-uri map
  std::map<std::string, map_uri_to_rpc> m_realm_registry;

  // map from session to rpc-by-id map
  std::map<session_handle, map_id_to_rpc, std::owner_less<session_handle>>
      m_session_to_rpcs;
};

} // namespace wampcc

#endif

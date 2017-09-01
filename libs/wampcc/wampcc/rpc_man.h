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

namespace wampcc {

class event_loop;
struct logger;
class kernel;

struct rpc_details
{
  enum
  {
    eInternal,
    eRemote
  } type;

  uint64_t registration_id; // 0 implies invalid
  std::string uri;
  session_handle session;
  on_call_fn user_cb; // applies only for eInternal
  void * user; // applies only for eInternal
  rpc_details() : registration_id( 0 ), user(nullptr) {}
};

typedef std::function< void(const rpc_details&) > rpc_added_cb;

class rpc_man
{
public:
  rpc_man(kernel*, rpc_added_cb);

  // return the registion id
  uint64_t handle_inbound_register(wamp_session*,
                                   std::string uri);

  uint64_t register_internal_rpc(const std::string& realm,
                                 const std::string& uri,
                                 on_call_fn,
                                 void * user);


  rpc_details get_rpc_details( const std::string& rpcname,
                               const std::string& realm);

  void session_closed(std::shared_ptr<wamp_session>&);

private:
  rpc_man(const rpc_man&); // no copy
  rpc_man& operator=(const rpc_man&); // no assignment

  void register_rpc(session_handle, std::string realm, rpc_details& r);

  logger & __logger; /* name chosen for log macros */
  rpc_added_cb m_rpc_added_cb;

  typedef  std::map< std::string, rpc_details >  rpc_registry;
  typedef  std::map< std::string, rpc_registry > realm_to_rpc_registry;

  std::mutex m_rpc_map_lock;
  realm_to_rpc_registry m_realm_to_registry;
  uint64_t m_next_regid;

  std::map<session_handle, std::list<rpc_registry::iterator>,
           std::owner_less<session_handle> > m_rpcs_for_session;

};

} // namespace wampcc

#endif

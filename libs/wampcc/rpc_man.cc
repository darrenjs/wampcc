/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/rpc_man.h"

#include "wampcc/event_loop.h"
#include "wampcc/kernel.h"
#include "wampcc/log_macros.h"
#include "wampcc/wamp_session.h"

#include <memory>

namespace wampcc {

/* Constructor */
rpc_man::rpc_man(kernel* k, rpc_added_cb added_cb, rpc_removed_cb removed_cb)
  : __logger(k->get_logger()), m_rpc_added_cb(added_cb), m_rpc_removed_cb(removed_cb), m_next_regid(1) {}

rpc_details rpc_man::get_rpc_details(const std::string& rpcname,
                                     const std::string& realm) {
  std::lock_guard<std::mutex> guard(m_rpc_map_lock);

  auto realm_iter = m_realm_registry.find(realm);

  if (realm_iter == m_realm_registry.end())
    return rpc_details(); // realm not found

  auto rpc_iter = realm_iter->second.find(rpcname);
  if (rpc_iter == realm_iter->second.end())
    return rpc_details(); // procedure not found

  return *(rpc_iter->second);
}


uint64_t rpc_man::register_internal_rpc(const std::string& realm,
                                        const std::string& uri, on_call_fn fn,
                                        void* user) {
  rpc_details r;
  r.uri = uri;
  r.user_cb = std::move(fn);
  r.user = user;
  r.type = rpc_details::eInternal;
  r.realm = realm;

  register_rpc(session_handle(), realm, r);

  if (m_rpc_added_cb)
    m_rpc_added_cb(r);

  return r.registration_id;
}


void rpc_man::handle_inbound_register(wamp_session& ws, t_request_id request_id,
                                      const std::string& ___uri,  const json_object& options) {
  /* EV thread */

  rpc_details r;
  r.registration_id = 0;
  r.uri = std::move(___uri);
  r.options = std::move(options);
  r.realm = ws.realm();
  r.session = ws.handle();
  r.type = rpc_details::eRemote;

  register_rpc(ws.handle(), ws.realm(), r);

  if (m_rpc_added_cb)
    m_rpc_added_cb(r);

  ws.registered(request_id, r.registration_id);
}


void rpc_man::register_rpc(session_handle session, std::string realm,
                           rpc_details& r) {
  if (r.uri.empty())
    throw wamp_error(WAMP_ERROR_INVALID_URI, "uri has zero length");

  if (!is_strict_uri(r.uri.c_str()))
    throw wamp_error(WAMP_ERROR_INVALID_URI, "uri fails strictness check");

  std::lock_guard<std::mutex> guard(m_rpc_map_lock);

  map_uri_to_rpc& realm_index = m_realm_registry[realm];

  auto rpc_iter = realm_index.find(r.uri);
  if (rpc_iter != realm_index.end()) {
    LOG_WARN("ignoring duplicate procedure registration for " << realm << ":"
                                                              << r.uri);
    throw wamp_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
  }

  r.registration_id = m_next_regid++;
  std::shared_ptr<rpc_details> rpc = std::make_shared<rpc_details>(r);
  realm_index.insert(std::make_pair(rpc->uri, rpc));

  auto& rpcs_for_session = m_session_to_rpcs[session];
  rpcs_for_session[rpc->registration_id] = std::move(rpc);

  LOG_INFO("procedure registered, " << r.registration_id << ", " << realm
                                    << "::" << r.uri);
}


void rpc_man::session_closed(std::shared_ptr<wamp_session>& session) {
  /* EV thread */

  std::lock_guard<std::mutex> guard(m_rpc_map_lock);

  auto realm_iter = m_realm_registry.find(session->realm());
  if (realm_iter != m_realm_registry.end()) {
    map_uri_to_rpc& rpcs_for_realm = realm_iter->second;
    auto session_iter = m_session_to_rpcs.find(session);
    if (session_iter != end(m_session_to_rpcs))
      for (auto& rpc_item : session_iter->second) {
        LOG_INFO("procedure unregistered, " //
                 << rpc_item.second->registration_id << ", " << session->realm()
                 << "::" << rpc_item.second->uri);

        /* Perform user-defined call-back, if present. */
        if (m_rpc_removed_cb)
            m_rpc_removed_cb(*(rpc_item.second));

        /* remove from realm index */
        rpcs_for_realm.erase(rpc_item.second->uri);
      }
  }

  /* remove all rpcs from session index */
  m_session_to_rpcs.erase(session);
}


/* Handle request to unregister a single procedure */
void rpc_man::handle_inbound_unregister(wamp_session& session,
                                        t_request_id request_id,
                                        t_registration_id registration_id) {
  /* EV thread */

  std::lock_guard<std::mutex> guard(m_rpc_map_lock);

  auto session_iter = m_session_to_rpcs.find(session.handle());
  if (session_iter != m_session_to_rpcs.end()) {
    auto rpc_iter = session_iter->second.find(registration_id);
    if (rpc_iter != session_iter->second.end()) {
      LOG_INFO("procedure unregistered, " //
               << rpc_iter->second->registration_id << ", " << session.realm()
               << "::" << rpc_iter->second->uri);

      /* Perform user-defined call-back, if present. */
      if (m_rpc_removed_cb)
          m_rpc_removed_cb(*(rpc_iter->second));

      /* remove from realm index */
      auto realm_iter = m_realm_registry.find(session.realm());
      if (realm_iter != m_realm_registry.end())
        realm_iter->second.erase(rpc_iter->second->uri);

      /* remove from session index */
      session_iter->second.erase(rpc_iter);

      /* reply to client, indicate success */
      session.unregistered(request_id);
    }
    else {
      LOG_WARN("unregister failed, registration_id " //
               << registration_id << " not found");
      throw wamp_error(WAMP_ERROR_NO_SUCH_REGISTRATION);
    }
  }
  else {
    LOG_WARN("unregister failed, session #" //
             << session.unique_id() << " not found");
    throw wamp_error(WAMP_ERROR_NO_SUCH_REGISTRATION);
  }
}


json_array rpc_man::get_procedures(const std::string& realm) const
{
  std::lock_guard<std::mutex> guard(m_rpc_map_lock);

  auto realm_iter = m_realm_registry.find(realm);

  wampcc::json_array uris;

  // Note that it's not an error if the realm is not found in the map; that just
  // means no procedures have yet been registered.

  if (realm_iter != m_realm_registry.end()) {
    const map_uri_to_rpc & reg = realm_iter->second;
    uris.reserve(reg.size());
    for (auto & item : reg)
      uris.push_back(item.first);
  }

  return uris;
}


} // namespace wampcc

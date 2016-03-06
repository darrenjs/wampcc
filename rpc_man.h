#ifndef XXX_RPC_MAN_H
#define XXX_RPC_MAN_H

#include "WampTypes.h"

#include <jalson/jalson.h>
#include <event.h>  /* TODO: try to delete me */

#include <functional>
#include <map>
#include <string>
#include <mutex>
#include <memory>

namespace XXX {

class event_loop;
class client_service;
class Logger;

/* TODO: this is a duplcate definition. In fact, is this even needed now? I.e.,
 this structure is that a CALLEE-program will register with CALLEE-api
 (client_service).

 */


// TODO: need to decrecate this class
class  protocol_error : public std::runtime_error
{
public:

  static protocol_error runtime_error(const std::string __text)
  {
    return protocol_error(WAMP_RUNTIME_ERROR, __text, true);
  }

  protocol_error(const std::string __error_uri,
                 const std::string __text,
                 bool __close_session)
    : std::runtime_error( __text ),
      error_uri( __error_uri ),
      close_session( __close_session )
  {
  }

  virtual ~protocol_error()  {}

  std::string error_uri;
  bool close_session;

};


struct rpc_details
{
  enum
  {
    eInternal,
    eRemote
  } type;

  int         registration_id; // 0 implies invalid
  std::string uri;
  SID sid;
  session_handle sesionh;
  rpc_details() : registration_id( 0 ) {}
};

typedef std::function< void(const rpc_details*) > rpc_added_cb;

class rpc_man
{
public:
  rpc_man(Logger *, event_loop&, rpc_added_cb);
  ~rpc_man();

  // return the registion id
  int  handle_register_event(session_handle& sh,
                             jalson::json_array&);

  // TODO: what is this for?
  void invoke_rpc(jalson::json_array& jv);
  // TODO: what is this for?
  void handle_invocation(jalson::json_array& jv);

  // Register and RPC that is handled by the internal session
  int register_internal_rpc(const std::string& rpc_uri);

  // Start a CALL sequence to an RPC
  void call_rpc(std::string rpcname);

  rpc_details get_rpc_details( std::string rpcname );

private:
  rpc_man(const rpc_man&); // no copy
  rpc_man& operator=(const rpc_man&); // no assignment

  Logger *__logptr; /* name chosen for log macros */
  event_loop& m_evl;

  std::map< std::string, rpc_details* > m_rpc_map2;
  int m_next_regid;
  std::mutex                                        m_rpc_map_lock;
  rpc_added_cb     m_rpc_added_cb;
};

} // namespace XXX

#endif

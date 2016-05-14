#ifndef XXX_EVENT_H
#define XXX_EVENT_H

#include "Callbacks.h"

#include <jalson/jalson.h>

#include <functional>

namespace XXX {

struct Request_CB_Data;

struct event
{
  enum Type
  {
    session_state_event = 0,
    router_session_connect_fail,
    inbound_message,
    outbound_publish,
    function_dispatch
  } type;

  session_handle src;
  t_connection_id user_conn_id;
  std::string realm;  // TODO: long term, replace with an ID

  event(Type t,
        t_connection_id u = t_connection_id())
    : type(t),
      user_conn_id(u)
  {}

  virtual ~event(){}
};



struct ev_inbound_message : public event
{
  int msg_type; // WAMP message type
  jalson::json_array ja;

  void * user;
  Request_CB_Data* cb_data; // valid for responses to request

  unsigned int internal_req_id;

  ev_inbound_message(int __msgtype)
    : event(inbound_message),
      msg_type(__msgtype),
      user(nullptr),
      cb_data(nullptr)
  {
  }

  ~ev_inbound_message();
};


struct ev_session_state_event : public event
{
  bool is_open;
  session_error::error_code err;

  ev_session_state_event(bool __session_open,
                         session_error::error_code e)
  : event( event::session_state_event ),
    is_open( __session_open ),
    err( e )
  {}
};


struct ev_outbound_publish : public event
{
  std::string uri;
  jalson::json_value patch;  // TODO: maybe change to array?
  jalson::json_object opts;
  jalson::json_array args_list;
  jalson::json_object args_dict;
  bool use_patch;


  std::vector< session_handle > targets;

  ev_outbound_publish(const std::string & __topic_uri,
                      const jalson::json_value& __patch,
                      size_t reserve_size)
    : event( event::outbound_publish ),
      uri( __topic_uri ),
      patch( __patch ),
      use_patch(true)
  {
    targets.reserve( reserve_size );
  }

  ev_outbound_publish(const std::string & __topic_uri,
                      const jalson::json_object& __opts,
                      const jalson::json_array& __args_list,
                      const jalson::json_object& __args_dict,
                      size_t reserve_size)
    : event( event::outbound_publish ),
      uri( __topic_uri ),
      opts(__opts),
      args_list(__args_list),
      args_dict(__args_dict),
      use_patch(false)
  {
    targets.reserve( reserve_size );
  }

};


struct ev_router_session_connect_fail : public event
{
  int status;  /* 0 is no error */

  ev_router_session_connect_fail(t_connection_id __conn_id,
                                 int __status)
    : event( event::router_session_connect_fail, __conn_id),
      status(__status)
  {}

};

} // namespace xxx

#endif

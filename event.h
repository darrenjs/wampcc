#ifndef XXX_EVENT_H
#define XXX_EVENT_H

#include "Callbacks.h"

#include <jalson/jalson.h>

#include <functional>

namespace XXX {

struct event
{
  enum Type
  {
    session_state_event = 0,
    outbound_publish,
    function_dispatch
  } type;

  session_handle src;
  std::string realm;  // TODO: long term, replace with an ID

  event(Type t)
    : type(t)
  {}

  virtual ~event(){}
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

} // namespace xxx

#endif

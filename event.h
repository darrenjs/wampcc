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
    function_dispatch
  } type;

  session_handle src;

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

} // namespace xxx

#endif

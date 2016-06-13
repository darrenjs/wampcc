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
    e_null = 0,
    e_kill,
    function_dispatch
  } type;

  session_handle src; // TODO: need to remove

  event(Type t)
    : type(t)
  {}

  virtual ~event(){}
};

} // namespace xxx

#endif

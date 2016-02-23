#ifndef XXX_SESSIONLISTENER_H
#define XXX_SESSIONLISTENER_H

namespace XXX {

class Session;

class SessionListener
{
public:
  virtual ~SessionListener() {}

  virtual void session_closed(Session&) {}
};

} // namespace XXX

#endif

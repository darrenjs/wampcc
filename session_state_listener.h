#ifndef XXX_SESSION_STATE_LISTENER_H
#define XXX_SESSION_STATE_LISTENER_H

namespace XXX {

  class Session;

class session_state_listener
{
public:

  session_state_listener();
  virtual~session_state_listener();

  virtual void handle_session_state_event(Session*, bool);

};

} // namespace XXX

#endif

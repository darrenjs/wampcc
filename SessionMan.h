#ifndef __SESSIONMAN_H_
#define __SESSIONMAN_H_

#include "Common.h"
#include "Callbacks.h"

#include "SessionListener.h"
#include "Session.h"

#include <jalson/jalson.h>

#include <functional>
#include <map>
#include <mutex>
#include <vector>

namespace XXX {

  class IOHandle;
  class Session;

  class event_loop;
  class Logger;
  struct session_state_event;
  struct Request_CB_Data;

  typedef std::function<jalson::json_array (int) > build_message_cb;


  typedef std::function<void(Session*, bool) > session_state_cb;


class SessionMan : public SessionListener
{
public:
  SessionMan(Logger*, event_loop&);
  ~SessionMan();

  Session* create_session(IOHandle *, bool is_dealer);

//void send_all(const char* data);

  void close_all();

  void session_closed(Session&) override;

  void set_session_event_listener(session_state_cb);


  /* Can be called on the EV thread */
  void send_to_session(SID, jalson::json_array& msg);

  void send_request(SID destination,
                    int request_type,
                    unsigned int internal_req_id,
                    build_message_cb_v2);

  void send_to_session(SID destination,
                       build_message_cb_v4);

  void handle_event( session_state_event* );
  void handle_housekeeping_event( void );

private:

  void heartbeat_all();

  Logger *__logptr; /* name chosen for log macros */

  event_loop& m_evl;
  struct
  {
    std::mutex lock;
    std::map<SID, Session*> active;
    std::vector<Session*>   closed;
    uint64_t m_next;
  } m_sessions;

  session_state_cb m_session_event_cb;

};


} // namespace

#endif

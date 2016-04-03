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


  typedef std::function<void(session_state_event*) > session_state_cb;


class SessionMan : public SessionListener
{
public:
  SessionMan(Logger*, event_loop&);
  ~SessionMan();

  Session* create_session(IOHandle *, bool is_passive,
                          t_rsid router_session_id = 0);

//void send_all(const char* data);

  void close_all();

  void session_closed(Session&) override;

  void set_session_event_listener(session_state_cb);


  /* Can be called on the EV thread */
  //void send_to_session(SID, jalson::json_array& msg);
  void send_to_session(session_handle,
                       jalson::json_array& msg);
  void send_to_session(const std::vector<session_handle>&,
                       jalson::json_array& msg);

  void send_to_session(session_handle,
                       build_message_cb_v4);

  void send_request(session_handle ,
                    int request_type,
                    unsigned int internal_req_id,
                    build_message_cb_v2);

  void handle_event( session_state_event* );
  void handle_housekeeping_event( void );

  bool session_is_open(session_handle sh) const;



private:

  void send_to_session_impl(session_handle,
                            jalson::json_array& msg);
  void heartbeat_all();

  Logger *__logptr; /* name chosen for log macros */

  event_loop& m_evl;

  mutable struct
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

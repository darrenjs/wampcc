#ifndef XXX_EVENT_LOOP_H
#define XXX_EVENT_LOOP_H


#include <jalson/jalson.h>
#include "WampTypes.h"
#include "event.h"

#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <vector>

namespace XXX {

  class rpc_man;
  class SessionMan;
  class Logger;



class event_error : public std::runtime_error
{

public:

  std::string error_uri;
  bool is_fatal;

  int msg_type;
  int request_id;

  event_error(const std::string __error_uri,
              const std::string __text,
              bool __close_session = false)
    : std::runtime_error( __text ),
      error_uri( __error_uri ),
      is_fatal( __close_session ),
      msg_type(0),
      request_id(0)
  {
  }

  event_error(const std::string __error_uri)
    : std::runtime_error( "" ),
      error_uri( __error_uri ),
      is_fatal( false ),
      msg_type(0),
      request_id(0)
  {
  }

  static event_error runtime_fatal(const std::string __text)
  {
    return event_error(WAMP_RUNTIME_ERROR, __text, true);
  }

  static event_error bad_protocol(const std::string __text)
  {
    return event_error(WAMP_RUNTIME_ERROR, __text, true);
  }

  static event_error request_error(const std::string __error_uri,
                                   int __msg_type,
                                   int __request_id)
  {
    event_error e( __error_uri );
    e.msg_type = __msg_type;
    e.request_id = __request_id;

    return e;
  }

};



  typedef std::function<void(class event*) > event_cb;


  class event_loop
  {
  public:
    event_loop(Logger*);
    ~event_loop();

    void init();

    void push(event* e);

    void request_stop() { m_continue=false; }

    void set_rpc_man(rpc_man*);
    void set_session_man(SessionMan*);

    void set_handler(unsigned int eventid, event_cb handler);


  private:
    event_loop(const event_loop&); // no copy
    event_loop& operator=(const event_loop&); // no assignment


    void eventmain();

    void process_event(event* e);
    void process_event_error(event* e, event_error&);

    void process_event_InboundCall(event* e);
    void process_outbound_call(outbound_call_event*);
    void process_outbound_response(outbound_response_event *);
    void process_outbound_message(outbound_message *);
    void process_inbound_error(event* e);
    void process_inbound_yield(event* e);

    Logger *__logptr; /* name chosen for log macros */

    bool m_continue;  // TODO: make atomic?

    std::vector< std::shared_ptr<event> > m_queue;
    std::mutex m_mutex;
    std::condition_variable m_condvar;
    std::thread m_thread;

    rpc_man* m_rpcman;
    SessionMan* m_sesman;

    std::vector<event_cb> m_handlers;
};

} // namespace XXX

#endif

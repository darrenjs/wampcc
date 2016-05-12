#ifndef XXX_EVENT_LOOP_H
#define XXX_EVENT_LOOP_H


#include <jalson/jalson.h>
#include "WampTypes.h"
#include "event.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace XXX {


  class pubsub_man;
  class SessionMan;
  class Logger;

struct server_event_handler
{
  // std::function<void(ev_inbound_message*)> handle_inbound_CALL;
  std::function<void(ev_inbound_message*)> handle_inbound_PUBLISH;
  std::function<void(ev_inbound_message*)> handle_inbound_REGISTER;
  std::function<void(ev_inbound_message*)> handle_inbound_SUSCRIBE;
  std::function<void(ev_inbound_message*)> handle_inbound_YIELD;
};


struct client_event_handler
{
  // std::function<void(ev_inbound_subscribed*)> handle_inbound_SUBSCRIBED;
  // std::function<void(ev_inbound_message*)> handle_inbound_event;
  std::function<void(ev_router_session_connect_fail*)> handle_router_session_connect_fail;
};




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



  // typedef std::function<void(event*) > event_cb;
  // typedef std::function<void(ev_inbound_message*) > event_cb2;


  class event_loop
  {
  public:
    event_loop(Logger*);
    ~event_loop();

    void stop();

    void init();

    void push(event* e);
    void push(std::shared_ptr<event> sp);
    void push(std::function<void()> fn);

    void request_stop() { m_continue=false; }


    void set_pubsub_man(pubsub_man*);
    void set_session_man(SessionMan*);

    // void set_handler(unsigned int eventid, event_cb handler);
    // void set_handler2(unsigned int eventid, event_cb2 handler);
    void set_handler(client_event_handler h)  { m_client_handler=h; }
    void set_handler(server_event_handler h ) { m_server_handler=h;  }

  private:
    event_loop(const event_loop&); // no copy
    event_loop& operator=(const event_loop&); // no assignment


    void eventloop();
    void eventmain();

    void process_event(event* e);
    void process_event_error(event* e, event_error&);

    void process_event_InboundCall(event* e);
//    void process_outbound_call(outbound_call_event*);
    void process_outbound_response(outbound_response_event *);
    // void process_outbound_message(outbound_message *);
    // void process_inbound_error(event* e);
    // void process_inbound_yield(ev_inbound_message* e);
    // void process_outbound_subscribe(ev_outbound_subscribe* e);
    void process_outbound_publish(ev_outbound_publish* e);

    void hb_check();

    Logger *__logptr; /* name chosen for log macros */

    bool m_continue;  // TODO: make atomic?

    std::vector< std::shared_ptr<event> > m_queue;
    std::mutex m_mutex;
    std::condition_variable m_condvar;
    std::thread m_thread;


    pubsub_man* m_pubsubman;
    SessionMan* m_sesman;

    // std::vector<event_cb> m_handlers;
    // std::vector<event_cb2> m_handlers2;

    server_event_handler m_server_handler;
    client_event_handler m_client_handler;

    std::chrono::time_point<std::chrono::steady_clock> m_last_hb;


};

} // namespace XXX

#endif

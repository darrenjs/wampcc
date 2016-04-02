#ifndef XXX_PUBSUB_MAN_H
#define XXX_PUBSUB_MAN_H

#include <map>

namespace XXX {

class Logger;
class client_service;
class ev_inbound_publish;
class event;
class event_loop;
class managed_topic;
class SessionMan;
class session_state_event;

class pubsub_man
{
public:
  pubsub_man(Logger *, event_loop&, SessionMan&);
  ~pubsub_man();

  void handle_event(ev_inbound_publish*);
  void handle_subscribe(event* ev);
  void handle_event( session_state_event* );;

private:
  pubsub_man(const pubsub_man&); // no copy
  pubsub_man& operator=(const pubsub_man&); // no assignment

  Logger *__logptr; /* name chosen for log macros */
  event_loop& m_evl;
  SessionMan& m_sesman;

  std::map<std::string, managed_topic*> m_topics;
  size_t m_next_subscription_id;

};

} // namespace XXX

#endif

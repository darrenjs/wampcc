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


class pubsub_man
{
public:
  pubsub_man(Logger *, event_loop&);
  ~pubsub_man();

  void handle_event(ev_inbound_publish*);
  void handle_subscribe(event* ev);

private:
  pubsub_man(const pubsub_man&); // no copy
  pubsub_man& operator=(const pubsub_man&); // no assignment

  Logger *__logptr; /* name chosen for log macros */
  event_loop& m_evl;

  std::map<std::string, managed_topic*> m_topics;

};

} // namespace XXX

#endif

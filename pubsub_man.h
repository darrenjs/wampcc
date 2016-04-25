#ifndef XXX_PUBSUB_MAN_H
#define XXX_PUBSUB_MAN_H

#include "jalson/jalson.h"

#include <map>
#include <memory>

namespace XXX {

class Logger;
class client_service;
class ev_internal_publish;
class event_loop;
class managed_topic;
class SessionMan;
class ev_session_state_event;
class ev_inbound_message;

class pubsub_man
{
public:
  pubsub_man(Logger *, event_loop&, SessionMan&);
  ~pubsub_man();

  void handle_event(ev_internal_publish*);
  void handle_subscribe(ev_inbound_message* ev);
  void handle_event( ev_session_state_event* );
  void handle_inbound_publish(ev_inbound_message*);

private:
  pubsub_man(const pubsub_man&); // no copy
  pubsub_man& operator=(const pubsub_man&); // no assignment

  managed_topic* find_topic(const std::string& topic,
                            const std::string& realm,
                            bool allow_create);


  void update_topic(const std::string& topic,
                    const std::string& realm,
                    jalson::json_array& publish_msg);

  Logger *__logptr; /* name chosen for log macros */
  event_loop& m_evl;
  SessionMan& m_sesman;

  typedef  std::map< std::string, std::unique_ptr<managed_topic> > topic_registry;
  typedef  std::map< std::string, topic_registry >   realm_to_topicreg;
  realm_to_topicreg m_topics;
  size_t m_next_subscription_id;
};

} // namespace XXX

#endif

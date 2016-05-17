#ifndef XXX_PUBSUB_MAN_H
#define XXX_PUBSUB_MAN_H

#include "Callbacks.h"

#include "jalson/jalson.h"

#include <map>
#include <memory>

namespace XXX {

class Logger;
class event_loop;
struct managed_topic;
class wamp_session;
class kernel;
struct ev_session_state_event;

class pubsub_man
{
public:
  pubsub_man(kernel&);
  ~pubsub_man();

  void handle_event( ev_session_state_event* );
  void inbound_publish(std::string realm, std::string uri, jalson::json_array&);
  void handle_inbound_subscribe(wamp_session* ptr, jalson::json_array&);

  t_request_id internal_publish(const std::string& topic,
                                const std::string& realm,
                                const jalson::json_object& options,
                                wamp_args);

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

  typedef  std::map< std::string, std::unique_ptr<managed_topic> > topic_registry;
  typedef  std::map< std::string, topic_registry >   realm_to_topicreg;
  realm_to_topicreg m_topics;
  size_t m_next_subscription_id;
};

} // namespace XXX

#endif

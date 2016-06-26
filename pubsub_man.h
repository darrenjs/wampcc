#ifndef XXX_PUBSUB_MAN_H
#define XXX_PUBSUB_MAN_H

#include "Callbacks.h"

#include "jalson/jalson.h"

#include <map>
#include <memory>

namespace XXX {

class Logger;
struct managed_topic;
class wamp_session;
class kernel;

class pubsub_man
{
public:
  pubsub_man(kernel&);
  ~pubsub_man();

  void inbound_publish(std::string realm,
                       std::string uri,
                       jalson::json_object options,
                       wamp_args);

  uint64_t subscribe(wamp_session* ptr,
                     t_request_id request_id,
                     std::string uri,
                     jalson::json_object & options);

  void session_closed(session_handle sh);

private:
  pubsub_man(const pubsub_man&); // no copy
  pubsub_man& operator=(const pubsub_man&); // no assignment

  managed_topic* find_topic(const std::string& topic,
                            const std::string& realm,
                            bool allow_create);


  void update_topic(const std::string& topic,
                    const std::string& realm,
                    jalson::json_object options,
                    wamp_args args);

  Logger *__logptr; /* name chosen for log macros */

  typedef  std::map< std::string, std::unique_ptr<managed_topic> > topic_registry;
  typedef  std::map< std::string, topic_registry >   realm_to_topicreg;
  realm_to_topicreg m_topics;
  size_t m_next_subscription_id;
};

} // namespace XXX

#endif

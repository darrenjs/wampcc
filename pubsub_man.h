#ifndef XXX_PUBSUB_MAN_H
#define XXX_PUBSUB_MAN_H

#include <map>

namespace XXX {

class ev_inbound_publish;
class managed_topic;

class pubsub_man
{
  public:
    pubsub_man();
    ~pubsub_man();

  void handle_event(ev_inbound_publish*);

  private:
    pubsub_man(const pubsub_man&); // no copy
    pubsub_man& operator=(const pubsub_man&); // no assignment

  std::map<std::string, managed_topic*> m_topics;
};

} // namespace XXX

#endif

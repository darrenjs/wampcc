#include "pubsub_man.h"

#include "event.h"

namespace XXX {


class managed_topic
{
};

/* Constructor */
pubsub_man::pubsub_man()
{
}

/* Destructor */
pubsub_man::~pubsub_man()
{
}

void pubsub_man::handle_event(ev_inbound_publish* ev)
{
  // TODO: lock me?  Or will only be the event thread?

  std::cout << "TODO: need to generete events now, for topic " << ev->uri <<"\n";

  // find or create a topic
  auto iter = m_topics.find( ev->uri );
  if (iter == m_topics.end())
  {
    std::cout << "topic created: " << ev->uri << "\n";
    managed_topic * mt = new managed_topic();
    auto result = m_topics.insert(std::make_pair(ev->uri , mt));
    iter = result.first;
  }



}

} // namespace XXX

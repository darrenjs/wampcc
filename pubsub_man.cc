#include "pubsub_man.h"

#include "event.h"
#include "event_loop.h"
#include "Logger.h"

#include <list>

namespace XXX {


struct managed_topic
{
  std::list< session_handle > m_subscribers;

  // current upto date image of the value
  jalson::json_value image;
  // TODO: nees to also have ability to take a patch and apply it
};

/* Constructor */
pubsub_man::pubsub_man(Logger * logptr, event_loop&evl)
  : __logptr(logptr),
  m_evl(evl)
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

  for (auto it : iter->second->m_subscribers)
  {
    std::cout << "TODO: next need to send EVENT to session\n";
  }
}


void pubsub_man::handle_subscribe(event* ev)
{
  /* We have received an external request to subscribe to a top */

  // TODO: improve this parsing
  int request_id = ev->ja[1].as_sint();
  jalson::json_string uri = ev->ja[3].as_string();


  // TODO: find or create the topic.
  auto it = m_topics.find( uri );

  bool allow_auto_create = true;
  if (it == m_topics.end())
  {

    if (allow_auto_create)
    {
      managed_topic * mt = new managed_topic();
      auto insres = m_topics.insert(std::make_pair(uri,mt));
      it = insres.first;
    }
    else
    {
      throw event_error::request_error("wamp.error.invalid_uri",
                                       SUBSCRIBE, request_id);
    }


  }

  // TODO: dont allow same subscription twice?
  it->second->m_subscribers.push_back(ev->src);

  _INFO_("subscribed to topic '"<< uri<< "'");

  outbound_response_event* evout = new outbound_response_event();

  evout->destination   = ev->src;
  evout->response_type = SUBSCRIBED;
  evout->request_type  = SUBSCRIBE;
  evout->reqid         = request_id;

  m_evl.push( evout );

}


} // namespace XXX

#include "pubsub_man.h"

#include "event.h"
#include "event_loop.h"
#include "Logger.h"
#include "WampTypes.h"
#include "SessionMan.h"

#include <list>

namespace XXX {

/*
TODO: what locking is needed around this?

- as subs are added, they will READ.  need to sync the addition of the
  subscriber, with the series of images and updates it sees.

- as PUBLISH events arrive, they will write


*/
struct managed_topic
{
  std::vector< session_handle > m_subscribers;

  // current upto date image of the value
  jalson::json_value image;

  // Note, we are tieing the subscription ID direct to the topic.  WAMP does
  // allow this, and it has the benefit that we can perform a single message
  // serialisation for all subscribers.  Might have to change later if more
  // complex subscription features are supported.
  size_t subscription_id;

  managed_topic(size_t __subscription_id)
  : subscription_id(__subscription_id)
  {
  }
};

/* Constructor */
  pubsub_man::pubsub_man(Logger * logptr, event_loop&evl, SessionMan& sm)
  : __logptr(logptr),
    m_evl(evl),
    m_sesman( sm ),
    m_next_subscription_id(1)
{
}

/* Destructor */
pubsub_man::~pubsub_man()
{
}

/* Handle arrival of the a PUBLISH event, targeted at a topic.
 *
 */
void pubsub_man::handle_event(ev_inbound_publish* ev)
{
  /* EV thread */

  // TODO: lock me?  Or will only be the event thread?

  // find or create a topic
  managed_topic* mt = find_topic(ev->uri, ev->realm, true);
  if (!mt) return; // TODO: dont I need to thow an event error here? Or, is this purely an internal event?

  // apply the patch
  try
  {
    mt->image.patch(ev->patch.as_array());

    /*
      [ EVENT,
        SUBSCRIBED.Subscription|id,
        PUBLISHED.Publication|id,
        Details|dict,
        PUBLISH.Arguments|list,
        PUBLISH.ArgumentKw|dict
      ]
    */

    jalson::json_array msg;
    msg.push_back( EVENT );
    msg.push_back( mt->subscription_id ); // TODO: generate subscription ID
    msg.push_back( 2 ); // TODO: generate publication ID
    msg.push_back( jalson::json_value::make_object() );
    jalson::json_array& args = jalson::append_array(msg);
    msg.push_back( jalson::json_value::make_object() );
    args.push_back(ev->patch);

    m_sesman.send_to_session(mt->m_subscribers,
                             msg);

    // TODO EASY - dont need to use the event loop here, because we are in an
    // event handler, ie, alread on the event thread. Indeed, could even just call send_to_session from here?
    // ev_outbound_event * ev = new ev_outbound_event("TOPIC",
    //                                                mt->m_subscribers,
    //                                                msg);
    // m_evl.push( ev );
  }
  catch (const std::exception& e)
  {
    _ERROR_("patch failed: " << e.what());
  }
}


void pubsub_man::handle_subscribe(ev_inbound_message* ev)
{
  /* EV thread */

  /* We have received an external request to subscribe to a top */

  // TODO: improve this parsing
  int request_id = ev->ja[1].as_int();
  jalson::json_string uri = ev->ja[3].as_string();

  // find or create a topic
  _INFO_("SUBSCRIBE for " << ev->realm << "::" << uri);
  managed_topic* mt = find_topic(uri, ev->realm, true);

  if (!mt)
    throw event_error::request_error(WAMP_ERROR_INVALID_URI,
                                     SUBSCRIBE, request_id);
  {
    auto sp = ev->src.lock();
    if (!sp) return;
    mt->m_subscribers.push_back(ev->src);
    _INFO_("session " << *sp << " subscribed to topic '"<< uri<< "'");

    // TODO: probably could call the session manager directly here, instead of
    // going via the event loop. I.e., in this function, we should already be on
    // the event thread.
    outbound_response_event* evout = new outbound_response_event();

    evout->destination   = ev->src;
    evout->response_type = SUBSCRIBED;
    evout->request_type  = SUBSCRIBE;
    evout->reqid         = request_id;
    evout->subscription_id = mt->subscription_id;
    m_evl.push( evout );
  }

}

static bool compare_session(const session_handle& p1, const session_handle& p2)
{
  return ( !p1.owner_before(p2) && !p2.owner_before(p1) );
}

void pubsub_man::handle_event(session_state_event* ev)
{
  /* EV loop */

  // TODO: design of this can be improved, ie, we should track what topics a
  // session has subscribed too, rather than searching every topic.
  for (auto & realm_iter : m_topics)
    for (auto & item : realm_iter.second)
    {
      for (auto it = item.second->m_subscribers.begin();
           it != item.second->m_subscribers.end(); it++)
      {
        if (compare_session(*it, ev->src))
        {
          item.second->m_subscribers.erase( it );
          break;
        }
      }
    }
}


managed_topic* pubsub_man::find_topic(const std::string& topic,
                                      const std::string& realm,
                                      bool allow_create)
{
  auto realm_iter = m_topics.find( realm );
  if (realm_iter == m_topics.end())
  {
    if (allow_create)
    {
      std::cout << "CREATING realm: " << realm << "\n";
      auto result = m_topics.insert(std::make_pair(realm, topic_registry()));
      realm_iter = result.first;
    }
    else
      return nullptr;
  }

  auto topic_iter = realm_iter->second.find( topic );
  if (topic_iter ==  realm_iter->second.end())
  {
    if (allow_create)
    {
      std::cout << "CREATING topic: " << topic << "\n";
      auto result = realm_iter->second.insert(std::make_pair(topic, new managed_topic(m_next_subscription_id++)));
      topic_iter = result.first;
    }
    else return nullptr;
  }

  return topic_iter->second;
}

} // namespace XXX

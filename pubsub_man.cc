#include "pubsub_man.h"

#include "topic.h"
#include "event_loop.h"
#include "log_macros.h"
#include "WampTypes.h"
#include "SessionMan.h"
#include "kernel.h"
#include "wamp_utils.h"

#include <list>
#include <iostream>

namespace XXX {

/*
Thread safety for pubsub.

Currently the public methods:

  - inbound_publish

  - subscribe

... are both called on the event loop thead, so presently no need for any
synchronization around the managed topics.  Additionally for the addition of a
new subscriber, the synchronization of the initially snapshot followed by
updates is also acheived through the single threaded approach.
*/
struct managed_topic
{
  std::vector< std::weak_ptr<wamp_session> > m_subscribers;

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

  uint64_t next_publication_id() { return m_id_gen.next(); }

private:
  global_scope_id_generator m_id_gen;
};

/* Constructor */
pubsub_man::pubsub_man(kernel& k)
  : __logger(k.get_logger()),
    m_next_subscription_id(1)  /* zero used for initial snapshot */
{
}

pubsub_man::~pubsub_man()
{
  // destructor needed here so that unique_ptr can see the definition of
  // managed_topic
}


/*
static bool compare_session(const session_handle& p1, const session_handle& p2)
{
  return ( !p1.owner_before(p2) && !p2.owner_before(p1) );
}
*/

managed_topic* pubsub_man::find_topic(const std::string& topic,
                                      const std::string& realm,
                                      bool allow_create)
{
  auto realm_iter = m_topics.find( realm );
  if (realm_iter == m_topics.end())
  {
    if (allow_create)
    {
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
      std::unique_ptr<managed_topic> ptr(new managed_topic(m_next_subscription_id++));
      auto result = realm_iter->second.insert(std::make_pair(topic, std::move( ptr )));
      topic_iter = result.first;
    }
    else return nullptr;
  }

  return topic_iter->second.get();
}


void pubsub_man::update_topic(const std::string& topic,
                              const std::string& realm,
                              jalson::json_object options,
                              wamp_args args)
{
  /* EVENT thread */

  managed_topic* mt = find_topic(topic, realm, true);

  if (!mt)
  {
    LOG_WARN("Discarding update to non existing topic '" << topic << "'");
    return;
  }

  if (options.find(KEY_PATCH) != options.end() && args.args_list.is_array())
  {
    // apply the patch
    std::cout << "@" << topic << ", patch\n";
    std::cout << "BEFORE: " << mt->image << "\n";
    std::cout << "PATCH : " << args.args_list << "\n";
    jalson::json_array & change = args.args_list.as_array();
    mt->image.patch(change[0].as_array());
    std::cout << "AFTER : "  << mt->image << "\n";
    std::cout << "-------\n";
  }

  // broadcast event to subscribers

  jalson::json_array msg;
  msg.reserve(6);
  msg.push_back( EVENT );
  msg.push_back( mt->subscription_id );
  msg.push_back( mt->next_publication_id() );
  msg.push_back( std::move(options) );
  if (!args.args_list.is_null())
  {
    msg.push_back( args.args_list );
    if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
  }

  size_t num_active = 0;
  for (auto & item : mt->m_subscribers)
  {
    if (auto sp = item.lock())
    {
      sp->send_msg(msg);
      num_active++;
    }
  }

  // remove any expired sessions

  if (num_active != mt->m_subscribers.size())
  {
    std::vector< std::weak_ptr<wamp_session> > temp;
    temp.resize(num_active);
    for (auto item : mt->m_subscribers)
    {
      if (!item.expired())
        temp.push_back( std::move(item) );
    }
    mt->m_subscribers.swap( temp );
  }



}


/* Handle arrival of the a PUBLISH event, targeted at a topic. This will write
 * to a managed topic. */
void pubsub_man::inbound_publish(std::string realm,
                                 std::string topic,
                                 jalson::json_object options,
                                 wamp_args args)
{
  /* EV thread */

  update_topic(topic, realm, std::move(options), args);
}

/* Add a subscription to a managed topic.  Need to sync the addition of the
  subscriber, with the series of images and updates it sees. This is done via
  single threaded access to this class.
 */
uint64_t pubsub_man::subscribe(wamp_session* sptr,
                               t_request_id request_id,
                               std::string uri,
                               jalson::json_object & options)
{
  /* EV thread */

  /* We have received an external request to subscribe to a top */


  // validate the URI
  // TODO: implement Strict URIs

  if (uri.empty())
    throw wamp_error(WAMP_ERROR_INVALID_URI, "URI zero length");


  // find or create a topic
  managed_topic* mt = find_topic(uri, sptr->realm(), true);

  if (!mt) throw wamp_error(WAMP_ERROR_INVALID_URI);

  LOG_INFO("session " << sptr->unique_id() << " subscribing to '"<< uri<< "'");

  /* SUBSCRIBED acknowledgement */
  jalson::json_array subscribed_msg;
  subscribed_msg.reserve(3);
  subscribed_msg.push_back(SUBSCRIBED);
  subscribed_msg.push_back(request_id);
  subscribed_msg.push_back(mt->subscription_id);
  sptr->send_msg(subscribed_msg);

  /* for stateful topic must send initial snapshot */
  if (options.find(KEY_PATCH) != options.end())
  {
    XXX::wamp_args pub_args;
    pub_args.args_list = jalson::json_array();

    jalson::json_array patch;
    jalson::json_object& operation = jalson::append_object(patch);
    operation["op"]    = "replace";
    operation["path"]  = "";  /* replace whole document */
    operation["value"] = mt->image;

    pub_args.args_list.as_array().push_back(std::move(patch));
    pub_args.args_list.as_array().push_back(jalson::json_array()); // empty event

    jalson::json_object event_options;
    event_options[KEY_PATCH] = options[KEY_PATCH];
    event_options[KEY_SNAPSHOT] = 1;
    jalson::json_array snapshot_msg;
    snapshot_msg.reserve(5);
    snapshot_msg.push_back( EVENT );
    snapshot_msg.push_back( mt->subscription_id );
    snapshot_msg.push_back( 0 ); // publication id
    snapshot_msg.push_back( std::move(event_options) );
    snapshot_msg.push_back( pub_args.args_list );
    sptr->send_msg(snapshot_msg);
  }

  mt->m_subscribers.push_back(sptr->handle());

  return mt->subscription_id;
}


void pubsub_man::session_closed(session_handle /*sh*/)
{
  /* EV loop */

  // // design of this can be improved, ie, we should track what topics a session
  // // has subscribed too, rather than searching every topic.
  // for (auto & realm_iter : m_topics)
  //   for (auto & item : realm_iter.second)
  //   {

  //     for (auto it = item.second->m_subscribers.begin();
  //          it != item.second->m_subscribers.end(); it++)
  //     {
  //       if (compare_session( *it, sh))
  //       {
  //         item.second->m_subscribers.erase( it );
  //         break;
  //       }
  //     }
  //   }
}

} // namespace XXX

#include "pubsub_man.h"

#include "event.h"
#include "event_loop.h"
#include "Logger.h"
#include "WampTypes.h"
#include "SessionMan.h"
#include "kernel.h"

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
  std::vector< std::weak_ptr<wamp_session> > m_subscribers;

  // current upto date image of the value
  jalson::json_value image;


  std::pair<bool,jalson::json_value>  image_list;
  std::pair<bool,jalson::json_value> image_dict;

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
pubsub_man::pubsub_man(kernel& k)
  : __logptr(k.get_logger()),
    m_next_subscription_id(1)
{
}

pubsub_man::~pubsub_man()
{
  // destructor needed here so that unique_ptr can see the definition of
  // managed_topic
}

// /* Handle arrival of an internl PUBLISH event, targeted at a topic. */
// void pubsub_man::handle_event(ev_internal_publish* ev)
// {
//   /* EV thread */

//   // TODO: lock me?  Or will only be the event thread?

//   update_topic(ev->uri, ev->realm, ev->patch.as_array());
// }




static bool compare_session(const session_handle& p1, const session_handle& p2)
{
  return ( !p1.owner_before(p2) && !p2.owner_before(p1) );
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
                              wamp_args args)
{
  /* EVENT thread */

  // resolve topic
  managed_topic* mt = find_topic(topic, realm, true);

  // TODO: do we want to reply to the originating client, if we reject the
  // publish? Also, we can have other exceptions (below), e.g., patch
  // exceptions. Also, dont want to throw, if it is an internal update
  if (!mt) return;


  // apply the patch
  bool is_patch = false;  // TODO: add support for patch
  if (!is_patch)
  {

    // apply the new value
    if (args.args_list.is_null() == false)
    {
      mt->image_list.first  = true;
      mt->image_list.second = args.args_list;


      if (args.args_dict.is_null() == false)
      {
        mt->image_dict.first  = true;
        mt->image_dict.second = args.args_dict;
      }
    }

    // broadcast event to subscribers
    jalson::json_array msg;
    msg.push_back( EVENT );
    msg.push_back( mt->subscription_id );
    msg.push_back( 2 ); // TODO: generate publication ID
    msg.push_back( jalson::json_value::make_object() );
    if (!args.args_list.is_null())
    {
      msg.push_back( args.args_list );
      if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
    }


    for (auto item : mt->m_subscribers)
    {
      // TODO: try to track those sessions which are now dead?  Or, do that on the event thread?
      if (auto sp = item.lock()) sp->send_msg(msg);
    }

  }
  else
  {
    // try
    // {
    //   jalson::json_array& patch = publish_msg;
    //   mt->image.patch(patch);

    //   jalson::json_array msg;
    //   msg.push_back( EVENT );
    //   msg.push_back( mt->subscription_id ); // TODO: generate subscription ID
    //   msg.push_back( 2 ); // TODO: generate publication ID
    //   msg.push_back( jalson::json_value::make_object() );
    //   jalson::json_array& args = jalson::append_array(msg);
    //   msg.push_back( jalson::json_value::make_object() );
    //   args.push_back(patch);

    //   m_sesman.send_to_session(mt->m_subscribers,
    //                            msg);


    // }
    // catch (const std::exception& e)
    // {
    //   _ERROR_("patch failed: " << e.what());
    // }
  }
}


/* Handle arrival of the a PUBLISH event, targeted at a topic. */
void pubsub_man::inbound_publish(std::string realm,
                                 std::string topic,
                                 wamp_args args)
{
  /* EV thread */

  bool is_patch = false;

  if ( is_patch )
  {
    // // parse message
    // std::string & topic = ev->ja[ 3 ].as_string();
    // jalson::json_array & patch = ev->ja[ 4 ].as_array();

    // // update
    // update_topic(topic, ev->realm, patch);
  }
  else
  {
    // parse message
    update_topic(topic, realm, args);
  }
}

uint64_t pubsub_man::subscribe(wamp_session* sptr,
                               std::string uri)
{
  /* EV thread */

  /* We have received an external request to subscribe to a top */


  // validate the URI
  // TODO: implement Strict URIs

  if (uri.empty())
    throw wamp_error(WAMP_ERROR_INVALID_URI, "URI zero length");


  // find or create a topic
  _INFO_("SUBSCRIBE for " << sptr->realm() << "::" << uri);
  managed_topic* mt = find_topic(uri, sptr->realm(), true);

  if (!mt)
    throw wamp_error(WAMP_ERROR_INVALID_URI);


  mt->m_subscribers.push_back(sptr->handle());
  _INFO_("session " << sptr->unique_id() << " subscribed to topic '"<< uri<< "'");

  return mt->subscription_id;
}


void pubsub_man::session_closed(session_handle sh)
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
        if (compare_session( *it, sh))
        {
          item.second->m_subscribers.erase( it );
          break;
        }
      }

    }
}

} // namespace XXX

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
  std::vector< std::weak_ptr<Session> > m_subscribers;

  // current upto date image of the value
  jalson::json_value image;


  std::pair<bool,jalson::json_array>  image_list;
  std::pair<bool,jalson::json_object> image_dict;

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

void pubsub_man::handle_event(ev_session_state_event* ev)
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
        if (compare_session( *it, ev->src))
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


  t_request_id pubsub_man::publish(const std::string& /*topic*/,
                                   const std::string& /*realm*/,
                                 const jalson::json_object& /* options */,
                                   wamp_args /*wamps*/)
{
  /* USER thread */

  // TODO: this function needs implemntation.  Comes in on user thread, so need
  // to change that to come in on the EV thread.

  // this->update_topic(topic, realm, );
  // managed_topic* mt = find_topic(topic, realm, true);

  // // TODO: do we want to reply to the originating client, if we reject the
  // // publish? Also, we can have other exceptions (below), e.g., patch
  // // exceptions. Also, dont want to throw, if it is an internal update
  // if (!mt) return 0;

  // t_request_id publish_request_id = 717171; // TODO: generate publication ID

  // // broadcast event to subscribers
  // jalson::json_array msg;
  // msg.push_back( EVENT );
  // msg.push_back( mt->subscription_id );
  // msg.push_back( publish_request_id );
  // msg.push_back( jalson::json_value::make_object() );
  // if (!wamps.args_list.is_null()) msg.push_back( std::move(wamps.args_list) );
  // if (!wamps.args_list.is_null() && !wamps.args_dict.is_null()) msg.push_back( std::move(wamps.args_dict) );
  // m_sesman.send_to_session(mt->m_subscribers, msg);

  // return publish_request_id;
  return 0;
}


void pubsub_man::update_topic(const std::string& topic,
                              const std::string& realm,
                              jalson::json_array& publish_msg)
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
    jalson::json_array  * args_list = nullptr;
    jalson::json_object * args_dict = nullptr;

    jalson::json_value* jvptr;
    if ((jvptr = jalson::get_ptr(publish_msg, 4)))
    {
      if (jvptr->is_array())
      {
        args_list = &(jvptr->as_array());
      }
      else
      {
        _WARN_("ignoring malformed publish message");
      }
    }
    if ((jvptr = jalson::get_ptr(publish_msg, 5)))
    {
      if (jvptr->is_object())
      {
        args_dict = &(jvptr->as_object());
      }
      else
      {
        _WARN_("ignoring malformed publish message");
      }
    }

    // apply the new value
    if (args_list)
    {
      mt->image_list.first  = true;
      mt->image_list.second = *args_list;
    }
    if (args_dict)
    {
      mt->image_dict.first  = true;
      mt->image_dict.second = *args_dict;
    }

    // broadcast event to subscribers
    jalson::json_array msg;
    msg.push_back( EVENT );
    msg.push_back( mt->subscription_id );
    msg.push_back( 2 ); // TODO: generate publication ID
    msg.push_back( jalson::json_value::make_object() );
    if (args_list) msg.push_back( *args_list );
    if (args_list && args_dict) msg.push_back( *args_dict );


    for (auto item : mt->m_subscribers)
    {
      // TODO: should this be done here, or, on the dispatch thread?
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
                                 jalson::json_array & msg)
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
    update_topic(topic, realm, msg);
  }
}

void pubsub_man::handle_inbound_subscribe(Session* sptr,
                                          jalson::json_array& msg)
{
  /* EV thread */

  /* We have received an external request to subscribe to a top */


  // TODO: improve this parsing
  t_request_id request_id = msg[1].as_uint();
  jalson::json_string uri = msg[3].as_string();

  // find or create a topic
  _INFO_("SUBSCRIBE for " << sptr->realm() << "::" << uri);
  managed_topic* mt = find_topic(uri, sptr->realm(), true);

  // TODO: test that this causes an error response
  if (!mt)
    throw event_error::request_error(WAMP_ERROR_INVALID_URI,
                                     SUBSCRIBE, request_id);
  {
    mt->m_subscribers.push_back(sptr->handle());
    _INFO_("session " << sptr->unique_id() << " subscribed to topic '"<< uri<< "'");

    // TODO: maybe building and sending message here is not best approach. Possibly use a callback?
    jalson::json_array out;
    out.push_back(SUBSCRIBED);
    out.push_back(request_id);
    out.push_back(mt->subscription_id);
    sptr->send_msg(out);
  }

}

} // namespace XXX

#include "Topic.h"

#include "Session.h"
#include "Logger.h"

#include <iostream>
#include <memory>

namespace XXX {

/* Constructor */
Topic::Topic(const std::string name)
  : m_name(name)
{
}

/* Destructor */
Topic::~Topic()
{
}

void Topic::updateValue(const char* newstr)
{
  {
    std::lock_guard<std::mutex> guard( m_lock ); // lock table
    m_string = newstr;
  }

  // TODO: need to generate the update message, and write to the subscribers

  // TODO: here, I should have a JSON structure which represents the change

//  send(json_msg);

  // TODO: have a think about using shared pointers here, so that I dont have to
  // hold the lock while sending

  {

    std::lock_guard<std::mutex> guard( m_subscribers.lock );
    // TODO: has been commented out, need to change to use the new array based API
    // for (auto & i : m_subscribers.items)
    // {
    //   i->send_bytes( m_string.c_str(),  m_string.length() );
    // }
  }

}

void Topic::add_subscriber(Session* s)
{
  std::lock_guard<std::mutex> guard( m_subscribers.lock );
  m_subscribers.items.insert( s );
}

void Topic::publish(std::list<jalson::json_array>& updates)
{
  /*
    length
    [  "event",
       0,
       0,
       {},
       []
       {}
   ]
       [36, 5512315355, 4429313566, {}, [], {"color": "orange",
           "sizes": [23, 42, 7]}]

    ]

   */

  jalson::json_array msg;
  msg.push_back("event");
  msg.push_back(0);
  msg.push_back(0);
  msg.push_back(jalson::json_object());
  jalson::json_array &  detail = append_array ( msg );
  for (auto & obj : updates)
    detail.push_back( obj );

  // TODO: this is bad... dont want to have to encode msg each time in the
  // session, if we can avaoid it.
  {
    std::lock_guard<std::mutex> guard( m_subscribers.lock );
    for (auto & i : m_subscribers.items)
    {
      i->send_msg( msg );
    }
  }

}

void topic::add_observer(observer* ptr)
{
  m_observers.push_back(ptr);
}

void topic::notify(const jalson::json_value& patch)
{

  for (auto & item : m_observers2)
  {
    item.second(this, patch);
  }


}


void text_topic::update(const char* newstr)
{
  m_text = newstr;

  jalson::json_string patch( newstr );
  notify( patch );
}

} // namespace XXX

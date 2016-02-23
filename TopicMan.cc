#include "TopicMan.h"

#include "Topic.h"

#include <iostream>

namespace XXX {

/* Constructor */
TopicMan::TopicMan(Logger*logptr )
  : __logptr(logptr)
{
}

/* Destructor */
TopicMan::~TopicMan()
{
}

void TopicMan::subscribe_all(Session* s)
{
  std::lock_guard<std::mutex> guard(m_topics.lock);

  for (auto & i : m_topics.items)
  {
    std::cout << "adding session to topic\n";
    i -> add_subscriber( s );
  }

}

void TopicMan::add_topic(Topic* topic)
{
  std::lock_guard<std::mutex> guard(m_topics.lock);
  m_topics.items.push_back( topic );
}





} // namespace XXX

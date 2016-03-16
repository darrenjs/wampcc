#ifndef XXX_TOPIC_H
#define XXX_TOPIC_H

#include "Common.h"

#include <jalson/jalson.h>

#include <string>
#include <set>
#include <mutex>
#include <list>

namespace XXX {

  class Session;
  class topic;

// Base class for topics


  typedef std::function< void(const topic*) >  topic_cb;


class topic
{
public:

  class observer
  {
  public:
    virtual ~observer() {}
    virtual void on_change() = 0;
  };

public:
  topic(const std::string& uri)
    : m_uri(uri)
  {}

  const std::string& uri() const { return m_uri; }



  void add_observer( observer* );

  void add_observer(void* key, topic_cb cb)
  {
    m_observers2[key]=cb;
  }

protected:

  void notify();

private:
  std::string m_uri;
  std::vector< observer* > m_observers;
  std::map< void* , topic_cb > m_observers2;
};


class text_topic : public topic
{
public:
  text_topic(const std::string& uri)
    : topic( uri )
  {
  }

  void update(const char* newstr);
};

class Topic
{
  public:
  Topic(const std::string name);
  ~Topic();

  void updateValue(const char* newstr);

  void add_subscriber(Session*);


protected:

  void publish(std::list<jalson::json_array>&);

  private:
    Topic(const Topic&); // no copy
    Topic& operator=(const Topic&); // no assignment

  std::string m_name;

  std::string m_string;

  struct {
    std::mutex lock;
    std::set< Session* > items;
  } m_subscribers;

  // fat lock
  std::mutex m_lock;
};

} // namespace XXX

#endif

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

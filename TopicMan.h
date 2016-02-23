#ifndef XXX_TOPICMAN_H
#define XXX_TOPICMAN_H

#include <mutex>
#include <vector>

namespace XXX {

  class Session;
  class Topic;
  class Logger;

class TopicMan
{
  public:
    TopicMan(Logger*);
    ~TopicMan();

  void subscribe_all(Session*);

  void add_topic(Topic*);

  private:
    TopicMan(const TopicMan&); // no copy
    TopicMan& operator=(const TopicMan&); // no assignment

  Logger *__logptr; /* name chosen for log macros */

  struct {
    std::mutex lock;
    std::vector< Topic* > items;
  } m_topics;


};

} // namespace XXX

#endif

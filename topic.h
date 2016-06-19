#ifndef XXX_TOPIC_H
#define XXX_TOPIC_H

#include <jalson/jalson.h>

#include <string>
#include <set>
#include <mutex>
#include <list>

namespace XXX {

  class wamp_session;
  class topic;

// Base class for topics


  typedef std::function< void(const topic*,
                              const jalson::json_value&) >  topic_cb;


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


  virtual jalson::json_value snapshot() const = 0;

protected:

  void notify(const jalson::json_value& patch);

private:
  std::string m_uri;
  // TODO: lock?
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


  jalson::json_value snapshot() const;

private:
  std::string m_text;
};

} // namespace XXX

#endif

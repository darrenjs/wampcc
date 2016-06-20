#ifndef XXX_TOPIC_H
#define XXX_TOPIC_H

#include <jalson/jalson.h>

#include <string>
#include <set>
#include <mutex>
#include <list>
#include <memory>

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


class basic_text : public topic
{
public:
  basic_text(const std::string& uri)
    : topic( uri )
  {
  }

  void update(const char* newstr);


  jalson::json_value snapshot() const;

private:
  std::string m_text;
};

class topic_publisher;

class data_model_base
{
public:

  data_model_base(std::string model_type);
  virtual ~data_model_base();

  jalson::json_object & head() { return *m_head; }
  jalson::json_object & body() { return *m_body; }

  void add_publisher(topic_publisher*);

protected:

  void apply_model_patch(const jalson::json_array&);

private:
  data_model_base(const data_model_base&) = delete;
  data_model_base& operator=(const data_model_base&) = delete;

  jalson::json_value  m_model;
  jalson::json_object * m_head;
  jalson::json_object * m_body;

  std::vector<topic_publisher*> m_publishers;
};


class basic_text_model : public data_model_base
{
public:
  basic_text_model();
  basic_text_model(std::string);

  void set_value(std::string);
  const std::string& get_value() const;

  jalson::json_string * m_value;
};


class topic_publisher
{
public:
  topic_publisher(std::string uri,
                  data_model_base*);

  void add_wamp_session(std::weak_ptr<wamp_session> wp);

private:
  void publish_update(const jalson::json_array&);

  std::string m_uri;
  data_model_base * m_model;
  std::vector<std::weak_ptr<wamp_session>> m_sessions;

  friend data_model_base;
};

} // namespace XXX

#endif

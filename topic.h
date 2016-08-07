#ifndef XXX_TOPIC_H
#define XXX_TOPIC_H

#include "Callbacks.h"
#include "utils.h"
#include "wamp_session.h"

#include <jalson/jalson.h>

#include <string>
#include <mutex>
#include <list>

#define KEY_PATCH    "_p"
#define KEY_SNAPSHOT "_snap"

namespace XXX {

class dealer_service;
class wamp_session;


struct patch_observer
{
  std::function< void(const jalson::json_array& patch) > on_snapshot;

  std::function< void(const jalson::json_array& patch ,
                      const jalson::json_array& event) > on_update;
};


class topic
{
public:

  template<typename T>
  topic(std::string uri, T* model)
    : m_uri(uri),
      m_attach_to_model([model](patch_observer pub)
                        {
                          model->add_observer( std::move(pub) );
                        })
  {
  }

  void add_publisher(std::weak_ptr<wamp_session> wp);

  void add_publisher(std::string realm,
                     std::weak_ptr<dealer_service>);

private:

  std::string m_uri;
  std::function<void(patch_observer)> m_attach_to_model;
  std::vector<std::weak_ptr<wamp_session>> m_sessions;
  std::vector< std::tuple<std::string /* realm */, dealer_service*> > m_dealers;
};


class basic_text
{
public:
  typedef std::string internal_impl;

  struct observer
  {
    std::function< void(const std::string&) > on_change;
  };

  static const std::string key_reset;

  basic_text() = default;
  basic_text(std::string);

  std::string value() const;

  void assign(std::string);

  void add_observer(observer);
  void add_observer(patch_observer);

private:
  internal_impl m_impl;
  std::mutex m_write_mutex;
  mutable std::mutex m_read_mutex;
  observer_list<observer> m_observers;
};



template<typename T>
class model_subscription
{
public:
  model_subscription(std::shared_ptr<XXX::wamp_session>& ws,
                     std::string uri,
                     T handler)
    : m_uri( std::move(uri) ),
      m_event_handler( std::move(handler) )
  {
    auto fn = [=](XXX::subscription_event_type evtype,
                  const std::string& /*uri*/,
                  const jalson::json_object& details,
                  const jalson::json_array& args_list,
                  const jalson::json_object& args_dict,
                  void* /*user*/)
      {
        if (evtype == e_sub_update)
          m_event_handler.on_event(details, args_list, args_dict);
      };

    ws->subscribe(m_uri, {{KEY_PATCH, 1}}, std::move(fn), nullptr);
  }


  template<typename... MArgs>
  model_subscription(std::shared_ptr<XXX::wamp_session>& ws,
                     std::string uri,
                     MArgs&... args)
    : model_subscription( ws, uri, T( args... ) )
  {
  }

  const std::string& topic_uri() const { return m_uri; }

private:
  std::string m_uri;
  T m_event_handler;
};



class basic_list
{
public:
  typedef std::vector< jalson::json_value > internal_impl ;

  struct list_events
  {
    std::function< void(size_t, const jalson::json_value& val) > on_insert;
    std::function< void(size_t, const jalson::json_value& val) > on_replace;
    std::function< void(size_t) > on_erase;
    std::function< void(const internal_impl&) > on_reset;
  };

  jalson::json_array copy_value() const;

  static const std::string key_reset;
  static const std::string key_insert;
  static const std::string key_remove;
  static const std::string key_modify;

  void reset(const internal_impl&);
  void insert(size_t, jalson::json_value);
  void push_back(jalson::json_value);
  void replace(size_t pos, jalson::json_value);
  void erase(size_t pos);

  void add_observer(list_events);
  void add_observer(patch_observer);

  class bad_index : public std::runtime_error
  {
  public:
    bad_index(size_t i) : std::runtime_error("bad index"), m_i(i) {}
    size_t index() const { return m_i; }
  private:
    size_t m_i;
  };

private:

  void insert_impl(size_t, jalson::json_value);

  std::mutex m_write_mutex;
  mutable std::mutex m_read_mutex;
  internal_impl m_items;
  observer_list<list_events> m_observers;
};



/* Handle a subscription to a basic list source.  Converts JSON patches into
 * object actions.  */
template<typename T = basic_list>
class basic_list_subscription_handler
{
public:

  basic_list_subscription_handler(T& t)
  : m_target(t)
  {
  }

  void on_event(const jalson::json_object& details,
                const jalson::json_array&  args_list,
                const jalson::json_object& args_dict);

  T& target() { return m_target; }

private:
  T&  m_target;
};



template<typename T>
void basic_list_subscription_handler<T>::on_event(const jalson::json_object& details,
                                                  const jalson::json_array& args_list,
                                                  const jalson::json_object& /*args_dict*/)
{
  jalson::json_value jv = args_list;
  //  std::cout << "handler::on_event, " << jv << "\n" << "details:"<< jalson::json_value( details ) << "\n";
  const jalson::json_array * patch = nullptr;
  const jalson::json_array * event = nullptr;

  if (args_list.size() > 0 && args_list[0].is_array())
    patch = &args_list[0].as_array();

  if (args_list.size()>1 && args_list[1].is_array())
    event = &args_list[1].as_array();
  // TODO: check details; needs to have { ... "_p": 1 ... }


  if ( patch &&
       (patch->size()==1) &&
       ( details.find("_snap") != details.end() ) && // is snapshot
       patch->operator[](0).is_object()
    )
  {
    const jalson::json_object & patch_replace = patch->operator[](0).as_object();
    const jalson::json_object & patch_value   = jalson::get_ref(patch_replace, "value").as_object();
    const jalson::json_object & body   = jalson::get_ref(patch_value, "body").as_object();
    const jalson::json_array  & body_value = jalson::get_ref(body, "value").as_array();
    m_target.reset( body_value );
  }
  else if (patch)
  {
    if (event &&
        event->size()>1 &&
        event->at(0).is_string() &&
        event->at(1).is_int() &&
        event->at(0).as_string() == basic_list::key_insert &&
        patch &&
        patch->size()>0 &&
        patch->at(0).is_object()
      )
    {
      auto it = patch->at(0).as_object().find("value");
      if (it != patch->at(0).as_object().end())
      {
        m_target.insert(event->at(1).as_int(), it->second);
      }
    }
    else if (event &&
             event->size()>=2 &&
             event->at(0).is_string() &&
             event->at(1).is_int() &&
             event->at(0).as_string() == basic_list::key_remove
      )
    {
      m_target.erase(event->at(1).as_int());
    }
    else if (event &&
             event->size()>=2 &&
             event->at(0).is_string() &&
             event->at(1).is_int() &&
             event->at(0).as_string() == basic_list::key_modify &&
             patch &&
             patch->size()>0 &&
             patch->at(0).is_object()
      )
    {
      auto it = patch->at(0).as_object().find("value");
      if (it != patch->at(0).as_object().end())
      {
        m_target.replace(event->at(1).as_int(), it->second);
      }
    }
  }
}


} // namespace XXX

#endif

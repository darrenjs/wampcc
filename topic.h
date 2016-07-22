#ifndef XXX_TOPIC_H
#define XXX_TOPIC_H

#include <jalson/jalson.h>
#include "Callbacks.h"
#include "utils.h"
#include "wamp_session.h"

#include <iostream>
#include <string>
#include <set>
#include <mutex>
#include <list>
#include <memory>

namespace XXX {

class dealer_service;
class topic;
class wamp_session;

class data_model_base
{
public:

  data_model_base(std::string model_type);
  virtual ~data_model_base();

  jalson::json_value copy_document() const;

  void add_publisher(topic*);

protected:

  void apply_model_patch(const jalson::json_array&,
                         const jalson::json_array&);

  mutable std::mutex m_lock;

  jalson::json_value  m_model;
  jalson::json_object * m_head;
  jalson::json_object * m_body;

private:
  data_model_base(const data_model_base&) = delete;
  data_model_base& operator=(const data_model_base&) = delete;

  std::vector<topic*> m_publishers;
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


// TODO: do I still need to inherit?
class basic_list_model : public data_model_base
{
public:

  class index_error : public std::runtime_error
  {
  public:
    // TODO: add gettors, make private etc
    size_t index;
    enum operation_type
    {
      eInsert,
      eRemove,
      eModify
    } operation;
    index_error(size_t i, operation_type op)
      : runtime_error("index not valid"),
        index(i), operation (op)
    {}
  };

  static const std::string key_insert;
  static const std::string key_remove;
  static const std::string key_modify;

  basic_list_model();

  /* generate change events */
  void insert(size_t pos, jalson::json_value);
  void replace(size_t pos, jalson::json_value);
  void push_back(jalson::json_value);
  void erase(size_t pos);

  jalson::json_array copy_value() const ;


private:
  jalson::json_array * m_value;
};


class topic
{
public:
  topic(std::string uri,
        data_model_base*);

  void add_wamp_session(std::weak_ptr<wamp_session> wp);


  void add_target(std::string realm,
                  dealer_service*);

private:
  void publish_update(const jalson::json_array&, const jalson::json_array&);

  std::string m_uri;
  data_model_base * m_data_model;
  std::vector<std::weak_ptr<wamp_session>> m_sessions;
  jalson::json_object m_options;

  std::vector< std::tuple<std::string /* realm */, dealer_service*> > m_dealers;

  friend data_model_base;
};



template<typename T>
class model_subscription
{
public:
  const std::string& topic_uri() { return m_uri; }

  model_subscription(std::shared_ptr<XXX::wamp_session>& ws,
                     std::string uri,
                     T handler)
    : m_uri( std::move(uri) ),
      m_event_handler( handler )
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

    jalson::json_object sub_options = { {"_p", 1} };
    ws->subscribe(m_uri, std::move(sub_options), std::move(fn), nullptr);
  }


private:
  std::string  m_uri;
  T m_event_handler;
};


class basic_list_target
{
public:

  typedef std::vector< jalson::json_value > internal_repr ;

  /* Receive change events */
  struct observer
  {
    std::function<void()>  on_reset;
    std::function<void(size_t)> on_insert;
    std::function<void(size_t)> on_remove;
    std::function<void(size_t)> on_modify;
  };

  void add_observer(observer);

  void on_reset(const jalson::json_array &);
  void on_insert(size_t, jalson::json_value);
  void on_remove(size_t);
  void on_modify(size_t, jalson::json_value);

  std::vector< jalson::json_value > copy() const;


  // Danger: direct use of the internal list must be done so with
  // synchronisation via the internal mutex
  std::mutex&    internal_mutex() { return m_mutex; }
  internal_repr& internal_list()  { return m_items; }

private:
  mutable std::mutex m_mutex;
  internal_repr  m_items;
  observer_list<observer> m_observers;
};




template<typename T>
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

  T&  m_target;
};



template<typename T>
void basic_list_subscription_handler<T>::on_event(const jalson::json_object& details,
                                                  const jalson::json_array& args_list,
                                                  const jalson::json_object& /*args_dict*/)
{
  jalson::json_value jv = args_list;
  std::cout << "handler::on_event, " << jv << "\n" << "details:"<< jalson::json_value( details ) << "\n";
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
    m_target.on_reset( body_value );
  }
  else if (patch)
  {
    if (event &&
        event->size()>1 &&
        event->at(0).is_string() &&
        event->at(1).is_int() &&
        event->at(0).as_string() == basic_list_model::key_insert &&
        patch &&
        patch->size()>0 &&
        patch->at(0).is_object()
      )
    {

      auto it = patch->at(0).as_object().find("value");
      if (it != patch->at(0).as_object().end())
      {
        m_target.on_insert(event->at(1).as_int(), it->second);
      }
    }
    else if (event &&
             event->size()>=2 &&
             event->at(0).is_string() &&
             event->at(1).is_int() &&
             event->at(0).as_string() == basic_list_model::key_remove
      )
    {
      m_target.on_remove(event->at(1).as_int());
    }
    else if (event &&
             event->size()>=2 &&
             event->at(0).is_string() &&
             event->at(1).is_int() &&
             event->at(0).as_string() == basic_list_model::key_modify &&
             patch &&
             patch->size()>0 &&
             patch->at(0).is_object()
      )
    {
      auto it = patch->at(0).as_object().find("value");
      if (it != patch->at(0).as_object().end())
      {
        m_target.on_modify(event->at(1).as_int(), it->second);
      }
    }
  }
}




} // namespace XXX

#endif

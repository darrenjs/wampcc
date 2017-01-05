#ifndef XXX_DATA_MODEL_H
#define XXX_DATA_MODEL_H

#include "XXX/types.h"
#include "XXX/utils.h"
#include "XXX/wamp_session.h"

#include <jalson/jalson.h>

#include <string>
#include <mutex>
#include <list>

#include <iostream> // TODO: delete me

#define KEY_PATCH    "_p"
#define KEY_SNAPSHOT "_snap"

namespace XXX {

class dealer_service;
class model_publisher;


/** Abstract base class for all JSON data models */
class data_model
{
public:
  data_model();
  data_model(const data_model&);
  virtual ~data_model() = 0;

  virtual jalson::json_value snapshot() const = 0;

  /** Obtain a model_publisher, which is used to publish updates to the data
   * model on a particular topic URI. */
  model_publisher* create_publisher(std::string topic_uri);

protected:

  std::mutex& publisher_mutex() { return m_publishers_mutex; }

  std::vector<std::unique_ptr<model_publisher>> m_publishers;
  mutable std::mutex                            m_publishers_mutex;

  friend class model_publisher;
};


/**
 * Allow a data model to be published as a topic with a specific URI
 */
class model_publisher
{
public:

  model_publisher(std::string uri, data_model * model)
    : m_data_model(model),
      m_uri(uri)
  {
  }

  void add_publisher(std::weak_ptr<wamp_session> wp);

  void add_publisher(std::string realm,
                     std::weak_ptr<dealer_service>);

  const std::string& uri() const { return m_uri; }

  void publish_update(jalson::json_array patch, jalson::json_array event);

private:

  XXX::wamp_args prepare_snapshot();

  data_model * m_data_model;
  std::string m_uri;
  std::vector<std::weak_ptr<wamp_session>> m_sessions;
  std::vector< std::pair<std::string /* realm */, std::weak_ptr<dealer_service> > > m_dealers;
};


/* */
class string_model : public data_model
{
public:
  typedef std::string internal_impl;

  string_model() = default;
  string_model(std::string);
  string_model(const string_model&);

  std::string value() const;

  jalson::json_value snapshot() const override;

  // Rich API for modifying model state
  void assign(std::string);

private:

  /* The data model internal representation.  Some kind of representation of
   * current model state is required so that a snapshot can be provided when a
   * new publisher is added. This can either be a rich-model or a json-model. */
  internal_impl      m_value;
  mutable std::mutex m_value_mutex;
};



class model_sub_base
{
public:


  model_sub_base(std::shared_ptr<XXX::wamp_session>& ws,
                 std::string topic_uri);

  virtual ~model_sub_base() = 0;

  const std::string& topic_uri() const { return m_uri; }

protected:
  std::string m_uri;
  std::weak_ptr<XXX::wamp_session> m_session;
};


template<typename T, typename V>
class jmodel_common : public model_sub_base
{
public:
  typedef V  value_type;


  jmodel_common(std::shared_ptr<XXX::wamp_session>& ws,
                std::string topic_uri)
    : model_sub_base(ws, topic_uri)
  {
    // auto fn = [this](wamp_subscription_event e)
    //   {
    //     if (e.type == wamp_subscription_event::update)
    //       this->on_update(std::move(e.details), std::move(e.args));
    //   };

    // ws->subscribe(m_uri, {{KEY_PATCH, 1}}, std::move(fn), nullptr);
  }


  // typename T::model_type value() const
  // {
  //   std::lock_guard<std::mutex> guard(m_value_mutex);
  //   return m_value;
  // }

protected:
//  typename T::model_type  m_value;
  mutable std::mutex      m_value_mutex;
//  typename T::observer    m_observer;
};


class jmodel_sub;
struct jmodel_types
{
  struct observer
  {
    std::function< void(jmodel_sub&) > on_snapshot;
  };

  typedef jalson::json_value model_type;

  void hander()
  {
  }

};


// class jmodel_sub : public jmodel_common<jmodel_types>
// {
// public:
//   jmodel_sub
// };



// class jmodel_sub2 : public jmodel_common<jmodel_sub2, jalson::json_value>
// {
// public:
//   typedef jalson::json_value model_type;

//   struct observer
//   {
//     std::function< void(jmodel_sub2&) > on_snapshot;
//     std::function< void(jmodel_sub2&) > on_error;
//     std::function< void(jmodel_sub2&) > on_change;
//   };

//   jmodel_sub2(std::shared_ptr<XXX::wamp_session>& ws,
//               std::string topic_uri,
//               observer ob)
//     : jmodel_common(ws, std::move(topic_uri))
//   {
//   }

// private:

//   void on_update(jalson::json_object options, wamp_args args)
//   {
//   }

// };





class jmodel_sub : public model_sub_base
{
public:

  struct observer
  {
    std::function< void() > on_snapshot;
    std::function< void() > on_error;
    std::function< void() > on_change;

  };

  jmodel_sub(std::shared_ptr<XXX::wamp_session>& ws,
             std::string topic_uri,
             observer);

private:

  void on_update(jalson::json_object options, wamp_args args);

  jalson::json_value m_jmodel;
  observer m_observer;
};



class string_model_sub : public model_sub_base
{
public:

  struct observer
  {
    std::function< void() > on_change;
  };

  string_model_sub(std::shared_ptr<XXX::wamp_session>& ws,
                   std::string topic_uri,
                   observer);

private:

  void on_update(jalson::json_object options, wamp_args args);

  /* A mutex associated with the internal value is provided, because the arrival
   * of snapshot & events via the EV thread can happen at any time, and might
   * occur simultaneously with user use of an accessor method. */
  std::string        m_value;
  mutable std::mutex m_value_mutex;

  observer m_observer;
};


} // namespace

#endif

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
  typedef V value_type;
  typedef jmodel_common<T,V> base_type;

  jmodel_common(std::shared_ptr<XXX::wamp_session>& ws,
                std::string topic_uri)
    : model_sub_base(ws, topic_uri)
  {
    auto this_derived = derived();
    auto fn = [this_derived](wamp_subscription_event e)
      {
        if (e.type == wamp_subscription_event::update)
          this_derived->on_update(std::move(e.details), std::move(e.args));
      };

    ws->subscribe(m_uri, {{KEY_PATCH, 1}}, std::move(fn), nullptr);
  }

  value_type value() const
  {
    std::lock_guard<std::mutex> guard(m_value_mutex);
    return m_value;
  }

protected:

  /* A mutex associated with the internal value is provided, because the arrival
   * of snapshot & events via the EV thread can happen at any time, and might
   * occur simultaneously with user use of an accessor method. */
  value_type         m_value;
  mutable std::mutex m_value_mutex;

private:
    // Convenience method for CRTP
    T* derived()
    {
      return static_cast<T*>(this);
    }
};


class jmodel_subscription : public jmodel_common<jmodel_subscription, jalson::json_value>
{
public:

  struct observer
  {
    std::function< void(const jmodel_subscription&) > on_change;
  };

  jmodel_subscription(std::shared_ptr<XXX::wamp_session>& ws,
     std::string topic_uri)
    : base_type(ws, std::move(topic_uri))
  {
  }

private:
  void on_update(jalson::json_object options, wamp_args args);

  friend base_type;
};


class string_subscription : public jmodel_common<string_subscription, std::string>
{
public:

  struct observer
  {
    std::function< void(const string_subscription&) > on_change;
  };

  string_subscription(std::shared_ptr<XXX::wamp_session>& ws,
                      std::string topic_uri)
    : base_type(ws, std::move(topic_uri))
  {
  }

private:

  void on_update(jalson::json_object options, wamp_args args);

  observer m_observer;

  friend base_type;
};


} // namespace

#endif

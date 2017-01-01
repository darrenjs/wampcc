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


/* Handle a subscription to a basic text data source.  Converts topic-model
 * snapshot and events (which arrive as JSON patches) into model actions and
 * observer callbacks. */
class string_model_subscription_handler
{
public:

  struct observer
  {
    std::function< void(const string_model_subscription_handler&) > on_snapshot;
    std::function< void(const string_model_subscription_handler&) > on_event;
  };

  string_model_subscription_handler(observer ob)
  : m_observer(std::move(ob))
  {
    // TODO: check both callbacks are defined
  }

  string_model_subscription_handler(const string_model_subscription_handler& rhs)
  : m_observer(rhs.m_observer),
    m_value(rhs.value())
  {
  }

  void on_event(const jalson::json_object& details,
                const jalson::json_array&  args_list,
                const jalson::json_object& args_dict);

  string_model::internal_impl value() const
  {
    std::unique_lock<std::mutex> guard(m_value_mutex);
    return m_value;
  }

private:
  observer m_observer;

  /* A mutex associated with the internal value is provided, because the arrival
   * of snapshot & events via the EV thread can happen at any time, and might
   * occur simultaneously with user use of an accessor method. */
  string_model::internal_impl m_value;
  mutable std::mutex        m_value_mutex;
};


}

#endif

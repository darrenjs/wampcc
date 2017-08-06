/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_DATA_MODEL_H
#define WAMPCC_DATA_MODEL_H

#include "wampcc/types.h"
#include "wampcc/wamp_session.h"
#include "wampcc/json.h"

#include <string>
#include <mutex>
#include <list>

#define KEY_PATCH    "_p"
#define KEY_SNAPSHOT "_snap"

namespace wampcc {

class wamp_router;
class model_topic;

/** Abstract base class for all JSON patch-based data models */
class data_model
{
public:
  data_model();

  /** Copy constructor.  The list of observers is not copied. */
  data_model(const data_model&);

  virtual ~data_model() = 0;

  /** Obtain a model_topic, which is used to publish updates to the data model
   * on a particular topic URI. The lifetime of the returned refernce is managed
   * by the data_model instance. */
  model_topic& get_topic(const std::string& uri);

protected:

  /** Get the json-model representative of current state */
  virtual json_value snapshot() const = 0;

  void publish(const json_array&, const json_array&);

  mutable std::mutex m_model_topics_mutex;
  std::map<std::string, std::unique_ptr<model_topic>> m_model_topic_lookup;
  std::vector<model_topic*> m_model_topics;

  friend class model_topic;
};


/**
 * Allow a data model to be published as a topic with a specific URI. Instances
 * of these are created by calling data_model::get_topic
 */
class model_topic
{
public:
  void add_publisher(std::weak_ptr<wamp_session> wp);
  void add_publisher(std::string realm, std::weak_ptr<wamp_router>);
  const std::string& uri() const { return m_uri; }

private:
  void publish_update(json_array patch, json_array event);
  model_topic(std::string, data_model*);
  wampcc::wamp_args prepare_snapshot();
  data_model * m_data_model;
  std::string m_uri;
  std::vector<std::weak_ptr<wamp_session>> m_sessions;
  std::vector<std::pair<std::string /* realm */, std::weak_ptr<wamp_router>>> m_dealers;
  friend data_model;
};


class model_sub_base
{
public:
  model_sub_base(std::shared_ptr<wampcc::wamp_session>& ws,
                 std::string topic_uri);

  virtual ~model_sub_base() = 0;

  const std::string& topic_uri() const { return m_uri; }

protected:
  std::string m_uri;
  std::weak_ptr<wampcc::wamp_session> m_session;
};


template<typename T, typename V>
class jmodel_common : public model_sub_base
{
public:
  typedef V value_type;
  typedef jmodel_common<T,V> base_type;

  jmodel_common(std::shared_ptr<wampcc::wamp_session>& ws,
                std::string topic_uri)
    : model_sub_base(ws, topic_uri)
  {
    auto this_derived = derived();
    wampcc::on_subscribed_fn scb;  // TODO

    auto fn = [this_derived](wamp_session&, event_info info)
      {
        this_derived->on_update(std::move(info.details), std::move(info.args));
      };

    ws->subscribe(m_uri, {{KEY_PATCH, 1}}, scb, std::move(fn), nullptr);
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
    T* derived() { return static_cast<T*>(this); }// utilty for CRTP
};


class jmodel_subscription : public jmodel_common<jmodel_subscription, json_value>
{
public:

  struct observer
  {
    std::function< void(const jmodel_subscription&) > on_change;
  };

  jmodel_subscription(std::shared_ptr<wampcc::wamp_session>& ws,
                      std::string topic_uri,
                      observer);

private:
  void on_update(json_object options, wamp_args args);
  observer m_observer;
  friend base_type;
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

  json_value snapshot() const override;

  // Rich API for modifying model state
  void assign(std::string);

private:

  /* The data model internal representation.  Some kind of representation of
   * current model state is required so that a snapshot can be provided when a
   * new publisher is added. This can either be a rich-model or a json-model. */
  internal_impl      m_value;
  mutable std::mutex m_value_mutex;
};


class string_subscription : public jmodel_common<string_subscription, std::string>
{
public:

  struct observer
  {
    std::function< void(const string_subscription&) > on_change;
  };

  string_subscription(std::shared_ptr<wampcc::wamp_session>& ws,
                      std::string topic_uri, observer);

private:
  void on_update(json_object options, wamp_args args);
  observer m_observer;
  friend base_type;
};


/* */
class list_model : public data_model
{
public:
  typedef std::vector< json_value > internal_impl ;

  static const std::string key_reset;
  static const std::string key_insert;
  static const std::string key_remove;
  static const std::string key_modify;

  // modification rich api
  void reset(internal_impl);
  void insert(size_t, json_value);
  void push_back(json_value);
  void replace(size_t pos, json_value);
  void erase(size_t pos);

  class bad_index : public std::runtime_error
  {
  public:
    bad_index(size_t i) : std::runtime_error("bad index"), m_i(i) {}
    size_t index() const { return m_i; }
  private:
    size_t m_i;
  };

  /** Get a copy of the internal value */
  internal_impl value() const;

  json_value snapshot() const override;

private:

  void insert_impl(size_t, json_value);

  /* The data model internal representation.  Some kind of representation of
   * current model state is required so that a snapshot can be provided when a
   * new publisher is added. This can either be a rich-model or a json-model. */
  internal_impl      m_value;
  mutable std::mutex m_value_mutex;
};


class list_subscription : public jmodel_common<list_subscription, list_model::internal_impl >
{
public:

  struct observer
  {
    std::function< void(const list_subscription&) > on_reset;
    std::function< void(const list_subscription&, size_t pos) > on_insert;
    std::function< void(const list_subscription&, size_t pos) > on_erase;
    std::function< void(const list_subscription&, size_t pos) > on_replace;
  };

  list_subscription(std::shared_ptr<wampcc::wamp_session>& ws,
                    std::string topic_uri,
                    observer ob);

private:
  void on_update(json_object options, wamp_args args);
  observer m_observer;
  friend base_type;
};


} // namespace

#endif

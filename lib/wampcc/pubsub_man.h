/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_PUBSUB_MAN_H
#define WAMPCC_PUBSUB_MAN_H

#include "wampcc/types.h"
#include "wampcc/utils.h"
#include "jalson/jalson.h"

#include <map>
#include <memory>

namespace wampcc {

struct logger;
struct managed_topic;
class wamp_session;
class kernel;

class pubsub_man
{
public:
  pubsub_man(kernel*);
  ~pubsub_man();

  void inbound_publish(std::string realm,
                       std::string uri,
                       json_object options,
                       wamp_args);

  uint64_t subscribe(wamp_session* ptr,
                     t_request_id,
                     std::string uri,
                     json_object & options);

  void unsubscribe(wamp_session*,
                   t_request_id,
                   t_subscription_id);

  void session_closed(session_handle sh);

private:
  pubsub_man(const pubsub_man&); // no copy
  pubsub_man& operator=(const pubsub_man&); // no assignment

  managed_topic* find_topic(const std::string& topic,
                            const std::string& realm,
                            bool allow_create);


  void update_topic(const std::string& topic,
                    const std::string& realm,
                    json_object options,
                    wamp_args args);

  logger & __logger; /* name chosen for log macros */

  typedef  std::map< std::string, std::unique_ptr<managed_topic> > topic_registry;
  typedef  std::map< std::string, topic_registry >   realm_to_topicreg;
  typedef  std::map< t_subscription_id,  managed_topic*>  subscriptionid_registry;
  realm_to_topicreg m_topics;
  t_subscription_id m_next_subscription_id;
  subscriptionid_registry m_subscription_registry;

  uri_regex m_uri_regex;
};

} // namespace wampcc

#endif

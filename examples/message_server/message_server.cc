/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <memory>
#include <iostream>
#include <sstream>

class message_server
{
public:
  message_server();

  ~message_server();


  std::future<void>& shutdown_future() { return m_shutdown_future;}

private:
  std::string  m_public_realm;
  std::string  m_private_realm;
  std::unique_ptr<wampcc::kernel>         m_kernel;
  std::shared_ptr<wampcc::wamp_router> m_dealer;

  struct message_topic
  {
    wampcc::string_model data;
    wampcc::model_topic & publisher;

    message_topic(const std::string& uri)
      : publisher(data.get_topic(uri))
    {
    }

    message_topic(const message_topic& rhs)
    : data(rhs.data),
      publisher(data.get_topic(rhs.publisher.uri()))
    {
    }
  };


  std::map<std::string, message_topic> m_topics;
  std::mutex m_topics_mutex;

  void rpc_message_set(wampcc::wamp_invocation&);
  void rpc_message_list(wampcc::wamp_invocation&);
  void rpc_shutdown(wampcc::wamp_invocation&);

  std::promise<void> m_shutdown_pomise;
  std::future<void>  m_shutdown_future;
};


message_server::message_server()
  : m_public_realm("default_realm"),
    m_private_realm("private"),
    m_kernel(new wampcc::kernel({}, wampcc::logger::stream(wampcc::logger::lockable_cout,
                                                           wampcc::logger::levels_all(),
                                                           true))),
    m_dealer(new wampcc::wamp_router(m_kernel.get(), nullptr)),
    m_shutdown_future(m_shutdown_pomise.get_future())

{
  wampcc::auth_provider server_auth;
  server_auth.provider_name = [](const std::string){ return "programdb"; };
  server_auth.policy = [&](const std::string& /*user*/,
                           const std::string& realm){
    if (realm == m_public_realm)
      return wampcc::auth_provider::auth_plan(wampcc::auth_provider::mode::open, {});
    else if (realm == m_private_realm)
      return wampcc::auth_provider::auth_plan(wampcc::auth_provider::mode::authenticate, {"wampcra"});
    else
      return wampcc::auth_provider::auth_plan(wampcc::auth_provider::mode::forbidden, {});
  };
  server_auth.user_secret = [](const std::string& /*user*/, const std::string& /*realm*/){ return "secret2"; };

  // TODO: would be preferable to obtain an internal_session object, and use that to register the RPC's etc.
  m_dealer->provide(m_public_realm,  "message_set",  {}, [this](wampcc::wamp_invocation& wi){rpc_message_set(wi); });
  m_dealer->provide(m_public_realm,  "message_list", {}, [this](wampcc::wamp_invocation& wi){rpc_message_list(wi);});
  m_dealer->provide(m_private_realm, "shutdown",     {}, [this](wampcc::wamp_invocation& wi){rpc_shutdown(wi);});

  int port = 55555;
  auto fut = m_dealer->listen("", std::to_string(port),
                              server_auth, wampcc::tcp_socket::addr_family::inet4);
  std::future_status status = fut.wait_for(std::chrono::seconds(1));
  switch(status)
  {
    case std::future_status::timeout :
      throw std::runtime_error("timeout during socket listen");
    case std::future_status::deferred :
      throw std::runtime_error("socket listen not attempted");
    case std::future_status::ready :
      wampcc::uverr ec = fut.get();
      if (ec != 0)
      {
        std::ostringstream os;
        os << "listen failed on port " << port << ", " << ec.message();
        throw std::runtime_error(os.str());
      }
      else
        std::cout << "listening on port " << port << std::endl;
  }
}


message_server::~message_server()
{
  /* Coordinate the proper close of the wamp_router and the kernel.  First we
   * shutdown the wamp_router, and then the kernel. */

  // TODO: Close the dealer, including any sessions that may currently connected. By
  // immediately performing the wait, this becomes a synchronous operation.
  m_dealer.reset();

  // Shutdown own kernel and its threads.
  m_kernel.reset();
}


void message_server::rpc_shutdown(wampcc::wamp_invocation&)
{
  m_shutdown_pomise.set_value();
}


void message_server::rpc_message_set(wampcc::wamp_invocation& invocation)
{
  /* Invoked on the wampcc EV thread */

  // Perform type checking of the received request
  if (invocation.args.args_list.size() < 1)
    throw std::runtime_error("missing message_key");

  if (invocation.args.args_list[0].is_string() == false)
    throw std::runtime_error("message_key must be a string");

  if (invocation.args.args_list.size() < 2)
    throw std::runtime_error("missing value");

  if (invocation.args.args_list[1].is_string() == false)
    throw std::runtime_error("value must be a string");

  std::string key = invocation.args.args_list[0].as_string();

  wampcc::json_value topic_value;
  if (invocation.args.args_list.size() > 1)
    topic_value = invocation.args.args_list[1];


  {
    std::lock_guard<std::mutex> guard(m_topics_mutex);
    auto iter = m_topics.find(key);

    if (iter == m_topics.end())
    {
      std::cout << "Creating new topic: " << key << std::endl;
      // using emplace, because havent yet written the move constructors
      iter = m_topics.emplace( key, key ).first;
      iter->second.data.assign(topic_value.as_string());
      iter->second.publisher.add_publisher(m_public_realm, m_dealer);
    }
    else
      iter->second.data.assign(topic_value.as_string());
  }

  invocation.yield({}, {});
}


void message_server::rpc_message_list(wampcc::wamp_invocation& invocation)
{
  std::lock_guard<std::mutex> guard(m_topics_mutex);

  wampcc::json_array ja;
  ja.reserve(m_topics.size());

  for (auto const & item : m_topics)
    ja.push_back(item.first);

  invocation.yield(ja, {});
}


int main(int argc, char** argv)
{
  try
  {
    message_server my_server;
    my_server.shutdown_future().wait();
    return 0;
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}

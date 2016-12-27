#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/wamp_session.h"
#include "XXX/dealer_service.h"

#include <memory>
#include <iostream>

class message_server
{
public:
  message_server();
  ~message_server();


  std::future<void>& shutdown_future() { return m_shutdown_future;}

private:
  std::string  m_public_realm;
  std::string  m_private_realm;
  std::unique_ptr<XXX::kernel>         m_kernel;
  std::shared_ptr<XXX::dealer_service> m_dealer;

  struct message_topic
  {
    XXX::basic_text data;
    XXX::topic      topic;
    message_topic(const std::string& s)
      : topic(s, &data)
    {}
    message_topic(const message_topic& rhs)
    : data(rhs.data),
      topic(rhs.topic.uri(), &data)
    {}
  };
  std::map<std::string, message_topic> m_topics;
  std::mutex m_topics_mutex;

  void rpc_message_set(XXX::wamp_invocation&);
  void rpc_message_list(XXX::wamp_invocation&);
  void rpc_shutdown(XXX::wamp_invocation&);

  std::promise<void> m_shutdown_pomise;
  std::future<void>  m_shutdown_future;
};


message_server::message_server()
  : m_public_realm("public"),
    m_private_realm("private"),
    m_kernel(new XXX::kernel({}, XXX::logger::stdlog(std::cout,
                                                     XXX::logger::levels_all(),
                                                     true))),
    m_dealer(new XXX::dealer_service(m_kernel.get(), nullptr)),
    m_shutdown_future(m_shutdown_pomise.get_future())

{
  // TODO: how do we control who is able to connect to the dealer service? That
  // aspect needs to be managed from this class, i.e., we are the owner of the
  // actual message server.

  // TODO: here, we are using the same auth structures that a client would
  // use. Is that correct?

  // TODO: improve the auth object. how to allow open authentication?  e.g some
  // domains are public; others are private
  XXX::auth_provider server_auth;
  server_auth.provider_name = [](const std::string){ return "programdb"; };
  server_auth.permit_user_realm = [](const std::string& /*user*/, const std::string& /*realm*/){ return true; };
  server_auth.get_user_secret   = [](const std::string& /*user*/, const std::string& /*realm*/){ return "secret2"; };

  // TODO: would be preferable to obtain an internal_session object, and use that to register the RPC's etc.
  m_dealer->provide(m_public_realm,  "message_set",  {}, [this](XXX::wamp_invocation& wi){rpc_message_set(wi); });
  m_dealer->provide(m_public_realm,  "message_list", {}, [this](XXX::wamp_invocation& wi){rpc_message_list(wi);});
  m_dealer->provide(m_private_realm, "shutdown",     {}, [this](XXX::wamp_invocation& wi){rpc_shutdown(wi);});

  m_dealer->listen(55555, server_auth);
}


message_server::~message_server()
{
  /* Coordinate the proper close of the dealer_service and the kernel.  First we
   * shutdown the dealer_service, and then the kernel. */

  // TODO: Close the dealer, including any sessions that may currently connected. By
  // immediately performing the wait, this becomes a synchronous operation.
  m_dealer.reset();

  // Shutdown own kernel and its threads.
  m_kernel.reset();
}


void message_server::rpc_shutdown(XXX::wamp_invocation&)
{
  m_shutdown_pomise.set_value();
}


void message_server::rpc_message_set(XXX::wamp_invocation& invocation)
{
  /* Invoked on the XXX EV thread */

  // Perform type checking of the received request
  if (invocation.arg_list.size() < 1)
    throw std::runtime_error("missing message_key");

  if (invocation.arg_list[0].is_string() == false)
    throw std::runtime_error("message_key must be a string");

  if (invocation.arg_list.size() < 2)
    throw std::runtime_error("missing value");

  if (invocation.arg_list[1].is_string() == false)
    throw std::runtime_error("value must be a string");

  std::string key = invocation.arg_list[0].as_string();

  jalson::json_value topic_value;
  if (invocation.arg_list.size() > 1)
    topic_value = invocation.arg_list[1];

  std::map<std::string, message_topic>::iterator iter;
  {
    std::unique_lock<std::mutex> guard(m_topics_mutex);
    iter = m_topics.find(key);

    if (iter == m_topics.end())
    {
      iter = m_topics.insert(std::make_pair(key, message_topic(key))).first;
      iter->second.topic.add_publisher(m_public_realm, m_dealer);
    }
  }

  iter->second.data.assign(topic_value.as_string());
  invocation.yield({}, {});
}


void message_server::rpc_message_list(XXX::wamp_invocation& invocation)
{
  std::unique_lock<std::mutex> guard(m_topics_mutex);

  jalson::json_array ja;
  ja.reserve(m_topics.size());

  for (auto const & item : m_topics)
    ja.push_back(item.first);

  invocation.yield(ja, {});
}



int main(int argc, char** argv)
{
  try
  {
    message_server mserv;
    mserv.shutdown_future().wait();
    return 0;
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}

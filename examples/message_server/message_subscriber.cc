#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/data_model.h"
#include "XXX/tcp_socket.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <iostream>


int main(int argc, char** argv)
{
  try
  {
    auto __logger = XXX::logger::stdlog(std::cout,
                                        XXX::logger::levels_upto(XXX::logger::eInfo), 1);
    XXX::kernel the_kernel({}, __logger);

    // subscription arguments
    XXX::wamp_args args;

    /* Create a socket */
    std::unique_ptr<XXX::tcp_socket> sock(new XXX::tcp_socket(&the_kernel));

    /* Attempt to connect the socket to the peer */
    auto connect_timeout = std::chrono::seconds(3);
    auto fut = sock->connect("127.0.0.1", 55555);
    std::future_status status = fut.wait_for(connect_timeout);
    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    /* Create a wamp_session */
    std::promise<void> promise_on_close;
    std::shared_ptr<XXX::wamp_session> session = XXX::wamp_session::create<XXX::rawsocket_protocol>(
      &the_kernel,
      std::move(sock),
      [&promise_on_close](XXX::session_handle, bool is_open)
      {
        if (!is_open)
          promise_on_close.set_value();
      }, {});

    /* Logon to a WAMP realm, and wait for session to be deemed open */
    XXX::client_credentials credentials;
    credentials.realm="public";
    credentials.authid="peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn = []() -> std::string { return "secret2"; };

    auto session_open_fut = session->initiate_hello(credentials);

    auto logon_timeout = std::chrono::milliseconds(5000);
    if (session_open_fut.wait_for(logon_timeout) == std::future_status::timeout)
      throw std::runtime_error("time-out during session logon");

    /* --- Session is now open --- */
    std::cout << "session open" << std::endl;

    /* Subscribe to a topic */

    std::string topic_uri = "xxxx";

    XXX::string_model_subscription_handler::observer observer {
      [](const XXX::string_model_subscription_handler& src){
        std::cout << "snapshot: " << src.value() << std::endl;
      },
      [](const XXX::string_model_subscription_handler& src){
        std::cout << "update: " << src.value() << std::endl;
      }
    };

    // OR  ... hybrid approach
    //
    //    XXX::string_model_subscription_handler handler;
    //    handler.add_observer(on_snap, on_sub);


    // OR ... okay, advantage here, is that we do use the same type for sending
    // and receiving ... although, disdavantage is that now we have have to
    // touch all the code invovlded in publication (i.e. it is inside
    // string_model).
    //
    //    XXX::string_model target_model;
    //    target_model.add_observer( {on_snapshot, on_update} );



    XXX::string_model_subscription_handler handler ( observer );


    XXX::model_subscription<XXX::string_model_subscription_handler > model_subs(session,
                                                                              topic_uri,
                                                                              handler);

    // TODO: next, need to feed this into an object that has rich callbacks ...
    // TODO: this is an unresolved part of the API, ie, how to understand the object model
    // TODO:

    // Wait until we get disconnected
    promise_on_close.get_future().wait();
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}

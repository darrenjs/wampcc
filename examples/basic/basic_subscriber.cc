#include "XXX/kernel.h"
#include "XXX/tcp_socket.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <random>
#include <iostream>

using namespace XXX;

int main(int, char**)
{
  try
  {
    std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::stdlog(std::cout, 0xFF, 1) ));

    std::unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    auto fut = sock->connect("127.0.0.1", 55555);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    std::promise<void> ready_to_exit;

    std::shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&ready_to_exit](XXX::session_handle, bool is_open){
        if (!is_open)
          try {
            ready_to_exit.set_value();
          } catch (...) {}
      },
      {});

    /* Logon to a WAMP realm, and wait for session to be deemed open. */
    client_credentials credentials;
    credentials.realm="default_realm";
    credentials.authid="peter";
    credentials.authmethods = {"wampcra"};
    credentials.secret_fn = []() -> std::string { return "secret2"; };

    auto session_open_fut = session->initiate_hello(credentials);

    if (session_open_fut.wait_for(std::chrono::milliseconds(5000)) == std::future_status::timeout)
      throw std::runtime_error("time-out during session logon");

    /* Session is now open, subscribe to a topic. */
    XXX::subscribed_cb my_subscribed_cb = [session](XXX::t_request_id request_id, std::string uri, bool successful,
                                                    t_subscription_id subid, std::string error)
      {
        if (successful)
        {
          std::cout << "subscription successful for '"<<uri << "', subscription_id " << subid << std::endl;
        }
        else
        {
          std::cout << "subscription failed for '"<< uri << "', error: " << error << std::endl;
          session->close();
        }
      };
    session->subscribe("coin_toss", {},
                       my_subscribed_cb,
                       [](wamp_subscription_event ev){
                         for (auto & x : ev.args.args_list)
                           std::cout << x << " ";
                         std::cout << std::endl;
                       });

    /* Opps! This is a duplicate subscription.  This is okay; we will actually
     * only subscribe once. */
    session->subscribe("coin_toss", {},
                       my_subscribed_cb,
                       [](wamp_subscription_event ev){
                         for (auto & x : ev.args.args_list)
                           std::cout << x << " ";
                         std::cout << std::endl;
                       });


    ready_to_exit.get_future().wait();

    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}


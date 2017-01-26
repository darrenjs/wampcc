#include "XXX/kernel.h"
#include "XXX/tcp_socket.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <random>
#include <iostream>

using namespace XXX;

std::tuple<std::string, int> get_addr_port(int argc, char** argv)
{
  if (argc != 3)
    throw std::runtime_error("arguments must be: ADDR PORT");
  return std::tuple<std::string,int>(argv[1], std::stoi(argv[2]));
}

int main(int argc, char** argv)
{
  try
  {
    auto endpoint = get_addr_port(argc, argv);

    std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::stdout() ));

    std::unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    auto fut = sock->connect(std::get<0>(endpoint), std::get<1>(endpoint));
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    std::mutex session_closed_mutex;
    std::condition_variable session_closed_convar;
    bool session_has_closed = false;

    std::shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      [&](XXX::session_handle, bool is_open){
        if (!is_open)
          try {
            std::lock_guard<std::mutex> guard(session_closed_mutex);
            session_has_closed = true;
            session_closed_convar.notify_one();
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

    /* stay subscribed for a short interval */
    {
      std::unique_lock<std::mutex> guard(session_closed_mutex);
      session_closed_convar.wait_for(guard, std::chrono::seconds(5),
                                     [&](){ return session_has_closed; });
    }

    /* if we still have an open session, then now unsubscribe */
    if (session->is_open())
    {
      std::cout << "doing the unsubscribe\n";
      //session->unsubscribe(subscription_id, subscribed_cb);
    }

    /* wait for session to be closed by peer */
    {
      std::unique_lock<std::mutex> guard(session_closed_mutex);
      session_closed_convar.wait(guard, [&](){ return session_has_closed; });
    }

    /* cleanly shutdown the session */
    session->close().wait();

    return 0;
  }
  catch (std::exception& e)
  {
    std::cout << e.what() << std::endl;
    return 1;
  }
}


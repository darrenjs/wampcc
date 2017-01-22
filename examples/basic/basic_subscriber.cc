#include "XXX/kernel.h"
#include "XXX/tcp_socket.h"
#include "XXX/wamp_session.h"
#include "XXX/websocket_protocol.h"

#include <memory>
#include <random>
#include <iostream>

using namespace XXX;

int main(int, char**)
{
  try
  {
    std::unique_ptr<kernel> the_kernel( new XXX::kernel({}, logger::nolog() ));

    std::unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    auto fut = sock->connect("127.0.0.1", 55555);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    std::promise<void> ready_to_exit;

    std::shared_ptr<wamp_session> session = wamp_session::create<websocket_protocol>(
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
    XXX::subscribed_cb cb = [](XXX::t_request_id, bool successful, std::string error){}; // TODO
    session->subscribe("coin_toss", {}, cb, [](wamp_subscription_event ev){
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


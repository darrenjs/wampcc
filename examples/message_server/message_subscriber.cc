#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/data_model.h"
#include "XXX/tcp_socket.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <iostream>

/* Make repeated attempts to connect to the end-point, with each failed attempt
 * as separated by a rest interval before the next attempt. When a successful
 * connection is established, the connected socket is returned.*/
std::unique_ptr<XXX::tcp_socket> get_tcp_connection(const char* address,
                                                    int port,
                                                    XXX::kernel & the_kernel,
                                                    std::chrono::milliseconds internal)
{
  const auto connect_timeout = std::chrono::seconds(3);

  while (true)
  {
    std::unique_ptr<XXX::tcp_socket> sock(new XXX::tcp_socket(&the_kernel));

    try
    {
      /* Attempt to connect to the peer */
      auto fut = sock->connect(address, port);

      /* The connection attempt completes asynchronously, so wait for result */
      std::future_status status = fut.wait_for(connect_timeout);
      switch(status)
      {
        case std::future_status::timeout :
          throw std::runtime_error("timeout");
        case std::future_status::deferred :
          throw std::runtime_error("connect not attempted");
        case std::future_status::ready :
          fut.get(); // evaluate the future to throw any transported exceptions
          if (sock->is_connected())
            return std::move(sock);
      }
    }
    catch (std::exception& e)
    {
      std::cout << "connect failed, " << e.what() << std::endl;
      std::this_thread::sleep_for(internal);
    }
  }
}


int main_impl(int argc, char** argv)
{
  auto __logger = XXX::logger::stdlog(std::cout,
                                      XXX::logger::levels_upto(XXX::logger::eInfo), 1);
  XXX::kernel the_kernel({}, __logger);

  while (true)
  {
    /* Get a connected socket to the end-point */
    std::unique_ptr<XXX::tcp_socket> sock = get_tcp_connection("127.0.0.1",
                                                               55555,
                                                               the_kernel,
                                                               std::chrono::seconds(1));

    std::promise<void> promise_on_close;
    std::shared_ptr<XXX::wamp_session> session;
    try
    {
      /* Create a wamp session */
      session = XXX::wamp_session::create<XXX::rawsocket_protocol>(
        &the_kernel,
        std::move(sock),
        [&promise_on_close](XXX::session_handle, bool is_open)
        {
          if (!is_open)
            promise_on_close.set_value();
        }, {});

      /* Logon to a WAMP realm, which completes asynchronously, so we need wait
       * for session to fully open */
      XXX::client_credentials credentials;
      credentials.realm="public";
      credentials.authid="peter";
      credentials.authmethods = {"wampcra"};
      credentials.secret_fn = []() -> std::string { return "secret2"; };

      auto session_open_fut = session->initiate_hello(credentials);

      switch (session_open_fut.wait_for(std::chrono::milliseconds(5000)))
      {
        case std::future_status::timeout :
          throw std::runtime_error("logon timeout");
        case std::future_status::deferred :
          throw std::runtime_error("logon not attempted");
        case std::future_status::ready :
          session_open_fut.get(); // evaluate the future to throw any transported exceptions
          if (!session->is_open())
            throw std::runtime_error("session not opened");
      };

      /* --- Session is now open --- */
      std::cout << "session open" << std::endl;

      // subscription arguments
      XXX::wamp_args args;

      /* Subscribe to a topic */
      std::string topic_uri = "xxxx";

      // Wait until we get disconnected
      promise_on_close.get_future().wait();
      std::cout << "connection lost" << std::endl;
    }
    catch (std::exception & e)
    {
      std::cout << "wamp session error, " << e.what() << std::endl;

    }

    // perform proper cleanup and deletion of leftover session object
    if (session)
    {
      session->close().wait();
      session.reset();
    }

    // brief delay before making the next attemp to connect to the server
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}


int main(int argc, char** argv)
{
  try {
    return main_impl(argc, argv);
  }
  catch (std::exception&e) {
    std::cout << "error, " << e.what() << std::endl;
    return 1;
  }
}

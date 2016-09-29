#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/wamp_session.h"
#include "XXX/wamp_connector.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"
#include "XXX/dealer_service.h"
#include "test_common.h"

#include <iostream>

using namespace XXX;
using namespace std;


class internal_client
{
public:
  internal_client()
    : m_kernel(new kernel({}, logger::nolog())),
      m_dealer(new dealer_service(*(m_kernel.get()), nullptr ))
  {
  }

  int start()
  {
    auth_provider server_auth;
    server_auth.provider_name = [](const string){ return "programdb"; };
    server_auth.permit_user_realm = [](const string& /*user*/, const string& /*realm*/){ return true; };
    server_auth.get_user_secret   = [](const string& /*user*/, const string& /*realm*/){ return "secret2";};

    int port = 20000;
    while (port < 65536)
    {
      future<int> fut_listen_err = m_dealer->listen(port, server_auth);
      future_status status = fut_listen_err.wait_for(chrono::milliseconds(100));
      if (status == future_status::ready)
      {
        int err = fut_listen_err.get();
        if (err == 0)
        {
          cout << "listening on port: " << port << "\n";
          return port;
        }
      }
    }

    return 0;
  }

private:
  unique_ptr<kernel>         m_kernel;
  shared_ptr<dealer_service> m_dealer;
};



void test_control(int port)
{
  cout << "------------------------------\n";
  cout << "control test\n";
  cout << "------------------------------\n";
  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    cout << "attemping socket connection ...\n";
    auto wconn = wamp_connector::create(
      the_kernel.get(),
      "127.0.0.1", to_string(port),
      false);

    auto connect_status = wconn->completion_future().wait_for(chrono::milliseconds(100));
    if (connect_status == future_status::timeout)
      throw runtime_error("expected -- should have connected");
    cout << "    got socket connection\n";

    /* attempt to create a session */
    cout << "attemping session creation ...\n";
    promise<void> promise_on_close;
    shared_ptr<wamp_session> session = wconn->create_session<rawsocket_protocol>(
      [&promise_on_close](session_handle, bool is_open)
      {
        if (!is_open)
          promise_on_close.set_value();
      });
    cout << "    got session\n";

    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";
  }
  cout << "    scope complete\n";

  cout << "test success\n";
}



void test_WS_destroyed_after_kernel(int port)
{
  cout << "------------------------------\n";
  cout << "test ~WS after ~kernel\n";
  cout << "------------------------------\n";
  shared_ptr<wamp_session> ws_outer;
  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    cout << "attemping socket connection ...\n";
    auto wconn = wamp_connector::create(
      the_kernel.get(),
      "127.0.0.1", to_string(port),
      false);

    auto connect_status = wconn->completion_future().wait_for(chrono::milliseconds(100));
    if (connect_status == future_status::timeout)
      throw runtime_error("expected -- should have connected");
    cout << "    got socket connection\n";

    /* attempt to create a session */
    cout << "attemping session creation ...\n";
    promise<void> promise_on_close;
    shared_ptr<wamp_session> session = wconn->create_session<rawsocket_protocol>(
      [&promise_on_close](session_handle, bool is_open)
      {
        if (!is_open)
          promise_on_close.set_value();
      });
    cout << "    got session\n";

    cout << "assigning session to outer scope (causes wamp_session destruction after kernel destruction)\n";
    ws_outer = session;
    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";
  }
  cout << "    scope complete\n";
  cout << "test success\n";
}

/* Note, these tests will only succeed if the system has access to a network. */

int __main()
{
  return 0;
}


int main()
{
  try
  {
    internal_client iclient;
    int port = iclient.start();

    if (port == 0)
      throw runtime_error("failed to find an available port number for listen socket");

    test_control(port);
    test_WS_destroyed_after_kernel(port);

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

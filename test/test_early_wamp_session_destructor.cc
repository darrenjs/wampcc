#include "test_common.h"


using namespace XXX;
using namespace std;

void test_WS_destroyed_before_kernel(int port)
{
  cout << "---------- test_WS_destroyed_before_kernel ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));

    /* attempt to connect the socket */
    cout << "attemping socket connection ...\n";
    auto autofut = sock->connect("127.0.0.1", port);

    auto connect_status = autofut.get_future().wait_for(chrono::milliseconds(100));
    if (connect_status == future_status::timeout)
    {
      cout << "    failed to connect\n";
      return;
    }
    cout << "    got socket connection\n";

    /* attempt to create a session */
    cout << "attemping session creation ...\n";
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      *(the_kernel.get()),
      std::move(sock),
      session_cb, {});

    cout << "    got session\n";

    cout << "trigger ~wamp_session\n";
    session.reset();
    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";
  }
  cout << "    scope complete\n";

  assert(callback_status == e_close_callback_without_sp);

  cout << "test success\n";
}


int main()
{
  try
  {
    int starting_port_number = 21000;

    // share a common internal_client
    for (int i = 0; i < 50; i++)
    {
      internal_client iclient;
      int port = iclient.start(starting_port_number++);

      for (int j=0; j < 100; j++) {
        cout << "using shared iclient\n";
        test_WS_destroyed_before_kernel(port);
      }
    }

    // use one internal_client per test
    for (int i = 0; i < 5000; i++)
    {
      cout << "using dedicated iclient\n";
      internal_client iclient;
      int port = iclient.start(starting_port_number++);
      test_WS_destroyed_before_kernel(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

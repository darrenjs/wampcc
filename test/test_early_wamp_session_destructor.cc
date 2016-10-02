#include "test_common.h"


using namespace XXX;
using namespace std;

void test_WS_destroyed_before_kernel(int port)
{
  cout << "------------------------------\n";
  cout << "control test\n";
  cout << "------------------------------\n";

  callback_status = e_callback_not_invoked;

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
    shared_ptr<wamp_session> session = wconn->create_session<rawsocket_protocol>(session_cb);
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

    // share a common internal_client
    for (int i = 0; i < 10; i++)
    {
      internal_client iclient;
      int port = iclient.start();

      for (int j=0; j < 10; j++) {
        test_WS_destroyed_before_kernel(port);
      }
    }

    // use one internal_client per test
    for (int i = 0; i < 100; i++)
    {
      internal_client iclient;
      int port = iclient.start();
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

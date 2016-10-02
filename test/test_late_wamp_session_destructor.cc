#include "test_common.h"

using namespace XXX;
using namespace std;

// logging control
#ifdef TLOG
#undef TLOG
#define TLOG(X)
#endif

void test_WS_destroyed_after_kernel(int port)
{
  TLOG("----- test ~WS after ~kernel -----");

  callback_status = e_callback_not_invoked;

  shared_ptr<wamp_session> ws_outer;
  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    TLOG("attemping socket connection ...");
    auto wconn = wamp_connector::create(
      the_kernel.get(),
      "127.0.0.1", to_string(port),
      false);

    auto connect_status = wconn->completion_future().wait_for(chrono::milliseconds(1000));
    if (connect_status == future_status::timeout)
    {
      throw runtime_error("expected -- should have connected");
    }
    TLOG("got socket connection");

    /* attempt to create a session */
    TLOG("attemping session creation");
    shared_ptr<wamp_session> session = wconn->create_session<rawsocket_protocol>( session_cb );
    TLOG("got session");

    TLOG("assigning session to outer scope (causes wamp_session destruction after kernel destruction)");
    ws_outer = session;
    TLOG("exiting scope (will trigger kernel, io_loop, ev_loop destruction)");
  }
  TLOG("scope complete");
  TLOG("triggering ~wamp_session...");
  ws_outer.reset();
  TLOG("complete");

  // In this test, the kernel is deleted before the wamp_session is deleted (due
  // to the outer shared_ptr holding on to it). This ordering means that the
  // wamp_session is still available during the wamp_session callback.
  assert(callback_status == e_close_callback_with_sp);

  TLOG("test success");
}


int main()
{
  try
  {
    int loops = 1000;

    // share a common internal_client
    for (int i = 0; i < loops; i++)
    {
      internal_client iclient;
      int port = iclient.start();

      for (int j=0; j < 100; j++) {
        test_WS_destroyed_after_kernel(port);
      }
    }

    // use one internal_client per test
    for (int i = 0; i < loops; i++)
    {
      internal_client iclient;
      int port = iclient.start();
      test_WS_destroyed_after_kernel(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

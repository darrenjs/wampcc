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
    unique_ptr<tcp_socket> sock (new tcp_socket(the_kernel.get()));
    TLOG("attemping socket connection ...");
    auto autofut = sock->connect("127.0.0.1", port);

    auto connect_status = autofut.get_future().wait_for(chrono::milliseconds(1000));
    if (connect_status == future_status::timeout)
    {
      cout << "expected -- should have connected\n";
      return;
    }
    TLOG("got socket connection");

    /* attempt to create a session */
    TLOG("attemping session creation");
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      session_cb, {});

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


int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 20000;
    int loops = 500;

    if (argc>1)
      starting_port_number = atoi(argv[1]);


    // share a common internal_server
    for (int i = 0; i < loops; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);

      for (int j=0; j < 100; j++) {
        test_WS_destroyed_after_kernel(port);
      }
    }

    // use one internal_server per test
    for (int i = 0; i < loops; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
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

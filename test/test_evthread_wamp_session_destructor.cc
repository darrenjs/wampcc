#include "test_common.h"

using namespace XXX;
using namespace std;


void test_WS_destroyed_after_kernel(int port)
{
  cout << "------------------------------\n";
  cout << "test ~WS on EV thread\n";
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

    cout << "pushing session onto ev_loop, where is will stay until ~ev_loop\n";
    the_kernel->get_event_loop()->dispatch(std::chrono::milliseconds(1000*60),
                                           [session]()
                                           {
                                             cout << "this delayed event should never get called";
                                             return 0;
                                           } );

    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";
  }
  cout << "    scope complete\n";
  cout << "test success\n";
}

int main()
{
  try
  {
    internal_client iclient;
    int port = iclient.start();

    test_WS_destroyed_after_kernel(port);

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

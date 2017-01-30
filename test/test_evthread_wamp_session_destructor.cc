#include "test_common.h"

using namespace XXX;
using namespace std;


void test_WS_destroyed_on_ev_thread(int port)
{
  cout << "------------------------------\n";
  cout << "test ~WS on EV thread\n";
  cout << "------------------------------\n";

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    std::unique_ptr<XXX::tcp_socket> sock( new tcp_socket(the_kernel.get()) );

    cout << "attemping socket connection ...\n";
    auto fut = sock->connect("127.0.0.1", port);

    auto connect_status =fut.wait_for(chrono::milliseconds(100));

    if (connect_status == future_status::timeout)
      throw runtime_error("unexpected -- should have connected");
    cout << "    got socket connection\n";

    /* attempt to create a session */
    cout << "attemping session creation ...\n";
    shared_ptr<wamp_session> session = wamp_session::create<rawsocket_protocol>(
      the_kernel.get(),
      std::move(sock),
      nullptr, {});

    cout << "    got session\n";

    cout << "pushing session onto ev_loop, where it will stay until ~ev_loop\n";
    the_kernel->get_event_loop()->dispatch(std::chrono::milliseconds(1000*60),
                                           [session]()
                                           {
                                             cout << "this delayed event should never get called";
                                             return std::chrono::milliseconds(0);
                                           } );
    session.reset();
    cout << "exiting scope (will trigger kernel, io_loop, ev_loop destruction)...\n";
  }
  cout << "    scope complete\n";
  cout << "test success\n";
}

int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 22000;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    // share a common internal_server
    for (int i = 0; i < 50; i++)
    {
        internal_server iserver;
        int port = iserver.start(starting_port_number++);

        for (int j=0; j < 100; j++) {
          test_WS_destroyed_on_ev_thread(port);
        }
    }

    // use one internal_server per test
    for (int i = 0; i < 1000; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      test_WS_destroyed_on_ev_thread(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

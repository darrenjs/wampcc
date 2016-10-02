#include "test_common.h"

using namespace XXX;
using namespace std;

// #ifdef TLOG
// #undef TLOG
// #define TLOG(X)
// #endif

void test_wamp_connector_unused(int port)
{
  TLOG("----- test test_wamp_connector_unused -----");

  {
    unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

    /* attempt to connect the socket */
    TLOG("attemping socket connection ...");
    auto wconn = wamp_connector::create(
      the_kernel.get(),
      "127.0.0.1", to_string(port),
      false);

    TLOG("exiting scope (will trigger kernel, io_loop, ev_loop destruction)");
  }
  TLOG("scope complete");

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
        test_wamp_connector_unused(port);
      }
    }

    // use one internal_client per test
    for (int i = 0; i < loops; i++)
    {
      internal_client iclient;
      int port = iclient.start();
      test_wamp_connector_unused(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

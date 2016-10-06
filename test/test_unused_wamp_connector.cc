#include "test_common.h"
       #include <string.h>


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
    int starting_port_number = 23000;
    int loops = 1;

    // share a common internal_client
    for (int i = 0; i < loops; i++)
    {
      void * ptr;
      size_t sz;
      std::cout << "loop -->" << std::endl;
      {
        internal_client iclient;
        ptr = &iclient;
        sz = sizeof(iclient);
        int port = iclient.start(starting_port_number++);

        std::cout << "-->" << std::endl;
        for (int j=0; j < 1; j++) {
          test_wamp_connector_unused(port);
        }
        std::cout << "<--" << std::endl;
      }
      memset(ptr, 0, sz);
      std::cout << "loop <--" << std::endl;
    }

    // // use one internal_client per test
    // for (int i = 0; i < loops; i++)
    // {
    //   internal_client iclient;
    //   int port = iclient.start(starting_port_number++);
    //   test_wamp_connector_unused(port);
    // }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

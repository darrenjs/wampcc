#include "test_common.h"



using namespace XXX;
using namespace std;


void test_late_dealer_destructor()
{
  {
    int port = 23000;
    TLOG("----- test started -----");

    std::cout << "starting the ports\n";
    internal_client iclient;
    for (int i = 0; i < 1000; i++)
      iclient.start(port+i);

    std::cout << "port start complete\n";


    int connect_port = port;
    {
      TLOG("making short lived socket connections");
      for (int i =0; i < 100; i++)
      {
        auto wconn = wamp_connector::create(
          iclient.get_kernel(),
          "127.0.0.1",to_string(connect_port++),
          false);
        wconn->completion_future().wait_for(chrono::milliseconds(1000));
      }
    }

    TLOG("making short lived socket connections that reach end of scope");
    std::vector< std::shared_ptr<wamp_connector> > connectors;
    for (int i =0; i < 500; i++)
    {
      auto wconn = wamp_connector::create(
        iclient.get_kernel(),
        "127.0.0.1",to_string(connect_port++),
        false);
      connectors.push_back( wconn );
      wconn->completion_future().wait_for(chrono::milliseconds(1000));
    }

    std::cout << "killing the kernel...\n";
    iclient.reset_kernel();
    std::cout << "about to complete...\n";
  }
}



int main()
{
  try
  {
    test_late_dealer_destructor();
    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }
}

#include "test_common.h"



using namespace XXX;
using namespace std;


/**
 * Closing a kernel object before a single wamp_connector object is closed was
 * source of core dump (during wamp_connector destructor, it was trying to use
 * the io_loop of the kernel, which has destructed).  Here we have that test,
 * with a couple of variations.
 */
void test_late_dealer_destructor_variants(int variant = 0)
{
  TLOG("----- "<< __FUNCTION__ << "(" << variant << ") -----");

  static int count = 0;
  cout << count++ << endl;
  int port = -1;
  internal_server iserver;
  for (int i = 20000; i < 65000 && port==-1; i++)
  {
    try
    {
      port = iserver.start(i);
    }
    catch (...)
    {
      cout << "port " << i << " unavailable" << endl;
    }
  }

  if (port == -1)
    throw runtime_error("test failed to run, no listen port available");

  if (variant == 0) iserver.reset_kernel();

  if (iserver.get_kernel())
  {
    tcp_socket my_socket(iserver.get_kernel());
    auto fut = my_socket.connect("127.0.0.1", port);

    if (variant == 1) iserver.reset_kernel();

    fut.wait_for(chrono::milliseconds(1000));

    if (variant == 2) iserver.reset_kernel();
  }
}

void test_all_variants_of_test_late_dealer_destructor_variants()
{
  auto variants = {0,1,2};
  for (int i : variants)
    test_late_dealer_destructor_variants(1); // TODO: revert back to i instead of 1
}

// void test_late_dealer_destructor()
// {
//   {
//     TLOG("----- test started -----");
//     int port = -1;

//     std::cout << "starting the ports\n";
//     internal_server iserver;
//     for (int i = 20000; i < 65000 && port==-1; i++)
//     {
//       try
//       {
//         port = iserver.start(i);
//       }
//       catch (...)
//       {
//         cout << "port " << i << " unavailable" << endl;
//       }
//     }
//     if (port == -1)
//       throw runtime_error("test failed to run, no listen port available");

//     std::cout << "port start complete, " << port<<"\n";

//     {
//       TLOG("making short lived socket connections");
//       for (int i =0; i < 100; i++)
//       {
//         auto wconn = wamp_connector::create(
//           iserver.get_kernel(),
//           "127.0.0.1",to_string(connect_port++),
//           false);
//         wconn->completion_future().wait_for(chrono::milliseconds(1000));
//       }
//     }

//     TLOG("making short lived socket connections that reach end of scope");

//     auto wconn = wamp_connector::create(
//       iserver.get_kernel(),
//       "127.0.0.1",to_string(port),
//       false);

// //    iserver.reset_kernel();   <--- make another test, placing it here

//     wconn->completion_future().wait_for(chrono::milliseconds(1000));

//     // destroy kernel and IO resources prematurely
//     iserver.reset_kernel();
//   }
// }



int main()
{
  try
  {
    int repititions = 10000;

    for (int i = 0; i < repititions; i++)
      test_all_variants_of_test_late_dealer_destructor_variants();

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }
}

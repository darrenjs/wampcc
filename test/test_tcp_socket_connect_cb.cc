#include "test_common.h"

#include <wampcc/tcp_socket.h>

#include <stdexcept>
#include <map>

using namespace wampcc;
using namespace std;


void test_canonical_connect(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  {
    tcp_socket sock( the_kernel.get() );

    promise<int> on_callback;

    auto on_connect = [&on_callback](tcp_socket* sock, int status)
      {
        on_callback.set_value(status);
      };

    sock.connect("127.0.0.1", port, on_connect);

    auto fut = on_callback.get_future();
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting\n";
      fut.wait();
    }

    cout << "got connect result " << fut.get() << endl;

    if (sock.is_connected() == false)
      throw runtime_error("expected to be connected");

    sock.close().wait();
  }


  the_kernel.reset();
}


void test_future_and_socket_discarded(int port)
{
  cout << "---------- test_future_and_socket_discarded ----------\n";
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  bool lambda_called = false;
  shared_ptr<tcp_socket> sockptr(new tcp_socket(the_kernel.get()));

  auto on_connect = [&lambda_called](tcp_socket* sock, int status)
    {
      lambda_called = true;
    };

  sockptr->connect("127.0.0.1", port, on_connect);
  sockptr.reset();
  assert(lambda_called == true);
}


void test_future_and_socket_discarded_use_expired_resource(int port)
{
  cout << "---------- test_future_and_socket_discarded_use_expired_resource ----------\n";
  bool lambda_called = false;
  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

    unique_ptr<string> message (new string());
    unique_ptr<map<string,string> > cont (new map<string,string>());

    shared_ptr<tcp_socket> sockptr(new tcp_socket(the_kernel.get()));

    auto on_connect = [&message, &cont,&lambda_called](tcp_socket* sock, int status)
      {
        message->assign("callback is using a string that should still be alive");
        (*cont)["test1"]="a";
        (*cont)["test2"]="b";
        lambda_called = true;
      };

    sockptr->connect("127.0.0.1", port, on_connect);
    sockptr.reset();
  }
  assert(lambda_called == true);
}


void test_future_and_socket_discarded_after_close(int port)
{
  cout << "---------- test_future_and_socket_discarded_after_close ----------\n";
  bool lambda_called = false;
  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

    unique_ptr<string> message (new string());
    unique_ptr<map<string,string> > cont (new map<string,string>());

    shared_ptr<tcp_socket> sockptr(new tcp_socket(the_kernel.get()));

    auto on_connect = [&message, &cont,&lambda_called](tcp_socket* sock, int status)
      {
        message->assign("callback is using a string that should still be alive");
        (*cont)["test1"]="a";
        (*cont)["test2"]="b";
        lambda_called = true;
      };

    sockptr->connect("127.0.0.1", port, on_connect);
    sockptr->close();
    sockptr.reset();
  }
  assert(lambda_called == true);
}


void test_future_and_socket_discarded_v2(int port)
{
  // cout << "---------- test_future_and_socket_discarded_v2 ----------\n";
  // unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  // {
  //   std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
  //   sp->connect("127.0.0.1", port);
  // }
}


void test_connect_and_delete(int port)
{
  // cout << "---------- test_connect_and_delete(1)----------\n";

  // unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  // {
  //   tcp_socket my_socket_1(the_kernel.get());
  //   my_socket_1.connect("127.0.0.1", port);
  //   tcp_socket my_socket_2(the_kernel.get());
  //   my_socket_2.connect("127.0.0.1", port);
  //   tcp_socket my_socket_3(the_kernel.get());
  //   my_socket_3.connect("127.0.0.1", port);
  // }

  // cout << "---------- test_connect_and_delete(2) ----------\n";
  // {
  //   std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
  //   sp_1->connect("127.0.0.1", port);
  //   std::shared_ptr<tcp_socket> sp_2(new tcp_socket(the_kernel.get()));
  //   sp_2->connect("127.0.0.1", port);
  //   std::shared_ptr<tcp_socket> sp_3(new tcp_socket(the_kernel.get()));
  //   sp_3->connect("127.0.0.1", port);
  // }

}



int main(int argc, char** argv)
{
  int starting_port_number = 23100;
  int port;

  if (argc>1)
    starting_port_number = atoi(argv[1]);

  auto all_tests = [](int port)
  {
    test_canonical_connect(port);
    test_future_and_socket_discarded(port);
    test_future_and_socket_discarded_use_expired_resource(port);
    test_future_and_socket_discarded_after_close(port);
    test_future_and_socket_discarded_v2(port);
    test_connect_and_delete(port);
  };

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    all_tests(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);

    for (int i = 0; i < 500; i++)
      all_tests(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 5000; ++i)
      test_canonical_connect(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_future_and_socket_discarded(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 5000; ++i)
      test_future_and_socket_discarded_use_expired_resource(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 5000; ++i)
      test_future_and_socket_discarded_after_close(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_future_and_socket_discarded_v2(port);
  }
  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_connect_and_delete(port);
  }

  cout << "tests complete\n";

  return 0;
}

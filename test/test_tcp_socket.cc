#include "test_common.h"

#include <XXX/tcp_socket.h>

#include <stdexcept>

using namespace XXX;
using namespace std;


void test_unused_socket()
{
  cout << "---------- test_unused_socket ----------\n";
  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

  tcp_socket sock1( the_kernel.get() );

  vector< shared_ptr<tcp_socket> > sockets;
  sockets.push_back( shared_ptr<tcp_socket>(new tcp_socket(the_kernel.get())) );
  sockets.push_back( shared_ptr<tcp_socket>(new tcp_socket(the_kernel.get())) );

  tcp_socket sock2( the_kernel.get() );

  the_kernel.reset();
}

void test_uvwalk_initiates_close(int port)
{
  cout << "---------- test_uvwalk_closes_sockets ----------\n";
  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

  vector< shared_ptr<tcp_socket> > sockets;
  for (int i = 0; i < 5; i++)
  {
    shared_ptr<tcp_socket> sp (new tcp_socket(the_kernel.get()));
    sockets.push_back(sp);
    auto completed_future = sp->connect("127.0.0.1", port);
    completed_future.set_auto_wait(false);
  }
  the_kernel.reset();
}

void test_orderly_connect_wait_close(int port)
{
  cout << "---------- test_orderly_connect_wait_close ----------\n";
  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

  {
    tcp_socket my_socket(the_kernel.get());
    auto_future completed = my_socket.connect("127.0.0.1", port);
    completed.get_future().wait();
  }
}

/* This used to cause a deadlock, think it was due to the presence of the
 * second test in the same function. */
void test_connect_and_delete_v1(int port)
{
  cout << "---------- test_connect_and_delete_v1 ----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    tcp_socket my_socket(the_kernel.get());
    my_socket.connect("127.0.0.1", port);
  }

  cout << "---------- test_connect_and_delete_v1+ ----------\n";
  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }

}

void test_connect_and_delete_v2(int port)
{
  cout << "---------- test_connect_and_delete_v2 ----------\n";
  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }
}

void test_connect_and_delete_v3(int port)
{
  cout << "---------- test_connect_and_delete_v3 ----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    tcp_socket my_socket_1(the_kernel.get());
    my_socket_1.connect("127.0.0.1", port);
    tcp_socket my_socket_2(the_kernel.get());
    my_socket_2.connect("127.0.0.1", port);
    tcp_socket my_socket_3(the_kernel.get());
    my_socket_3.connect("127.0.0.1", port);
  }

  cout << "---------- test_connect_and_delete_v3+ ----------\n";
  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_2(new tcp_socket(the_kernel.get()));
    sp_2->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_3(new tcp_socket(the_kernel.get()));
    sp_3->connect("127.0.0.1", port);
  }

}


void test_connect_read_delete_v1(int port)
{
  cout << "---------- test_connect_read_delete_v1 ----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    tcp_socket my_socket_1(the_kernel.get());
    my_socket_1.connect("127.0.0.1", port);
    my_socket_1.start_read(0);
  }

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port);
    sp_1->close();
    try
    {
      sp_1->start_read(0);
      throw std::runtime_error("start_read expected to throw");
    }
    catch (...)
    {
      // good, caught exception
    }
  }

}




int main(int argc, char** argv)
{
  int starting_port_number = 23100;
  int port;

  if (argc>1)
    starting_port_number = atoi(argv[1]);

  auto all_tests = [](int port)
  {
    test_unused_socket();
    test_uvwalk_initiates_close(port);
    test_connect_and_delete_v1(port);
    test_connect_and_delete_v2(port);
    test_connect_and_delete_v3(port);
    test_orderly_connect_wait_close(port);
    test_connect_read_delete_v1(port);
  };

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    all_tests(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);

    for (int i = 0; i < 10; i++)
      all_tests(port);
  }

  // {
  //   internal_server iserver;
  //   port = iserver.start(starting_port_number++);
  //   for (int i = 0; i < 500; ++i)
  //     test_uvwalk_initiates_close(port);
  // }

  {
    for (int i = 0; i < 2000; ++i)
      test_unused_socket();
  }
  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_connect_and_delete_v1(port);
  }
  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_connect_and_delete_v2(port);
  }
  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_connect_and_delete_v3(port);
  }
  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 2000; ++i)
      test_orderly_connect_wait_close(port);
  }

  cout << "tests complete\n";

  return 0;
}

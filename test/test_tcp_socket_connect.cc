#include "test_common.h"

#include <XXX/tcp_socket.h>
#include <XXX/io_listener.h>
#include <XXX/io_loop.h>

#include <stdexcept>

using namespace XXX;
using namespace std;


void test_unused_socket()
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  tcp_socket sock( the_kernel.get() );
}

void test_canonical_connect(int port)
{
  cout << "---------- test_canonical_connect ----------\n";
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  {
    tcp_socket sock( the_kernel.get() );

    auto fut = sock.connect("127.0.0.1", port);

    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting\n";
      fut.wait();
    }

    cout << "got connect result\n";
    fut.get();

    if (sock.is_connected() == false)
      throw runtime_error("expected to be connected");
  }

  the_kernel.reset();
}


void test_future_and_socket_discarded(int port)
{
  cout << "---------- test_future_and_socket_discarded ----------\n";
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  {
    tcp_socket sock( the_kernel.get() );
    auto fut = sock.connect("127.0.0.1", port);
  }

  {
    tcp_socket sock( the_kernel.get() );
    sock.connect("127.0.0.1", port);
  }

  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    auto fut = sp->connect("127.0.0.1", port);
  }

  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }


  the_kernel.reset();
}



void test_future_and_socket_discarded_v2(int port)
{
  cout << "---------- test_future_and_socket_discarded_v2 ----------\n";
  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    std::shared_ptr<tcp_socket> sp(new tcp_socket(the_kernel.get()));
    sp->connect("127.0.0.1", port);
  }
}


void test_connect_and_delete(int port)
{
  cout << "---------- test_connect_and_delete(1)----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );
  {
    tcp_socket my_socket_1(the_kernel.get());
    my_socket_1.connect("127.0.0.1", port);
    tcp_socket my_socket_2(the_kernel.get());
    my_socket_2.connect("127.0.0.1", port);
    tcp_socket my_socket_3(the_kernel.get());
    my_socket_3.connect("127.0.0.1", port);
  }

  cout << "---------- test_connect_and_delete(2) ----------\n";
  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_2(new tcp_socket(the_kernel.get()));
    sp_2->connect("127.0.0.1", port);
    std::shared_ptr<tcp_socket> sp_3(new tcp_socket(the_kernel.get()));
    sp_3->connect("127.0.0.1", port);
  }

}





class socket_listener : public io_listener
{
public:

  /* Following this call, IO handle is invalidated and must not be used again */
  virtual void io_on_close()
  {
    cout << "io_on_close" << endl;
  }

  virtual void io_on_read(char*, size_t)
  {
    cout << "io_on_read" << endl;
  }

};



void test_connect_read_close(int port)
{
  cout << "---------- test_connect_read_close ----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

  socket_listener my_listener;

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    sp_1->connect("127.0.0.1", port);

    sp_1->start_read(&my_listener);
    sp_1->close();
  }

}


void test_connect_then_io_stop(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";

  unique_ptr<kernel> the_kernel( new kernel({}, logger::nolog() ) );

  socket_listener my_listener;

  {
    std::shared_ptr<tcp_socket> sp_1(new tcp_socket(the_kernel.get()));
    auto fut = sp_1->connect("127.0.0.1", port);

    fut.wait();
    the_kernel->get_io()->stop();

    // deletion of the socket will proceed fine, because completion of the IO
    // loop implies all sockets have been closed.
    sp_1.reset();
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
    test_canonical_connect(port);
    test_connect_then_io_stop(port);
    test_future_and_socket_discarded(port);
    test_future_and_socket_discarded_v2(port);
    test_connect_and_delete(port);
    test_connect_read_close(port);
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
    for (int i = 0; i < 2000; ++i)
      test_canonical_connect(port);
  }

  {
    internal_server iserver;
    port = iserver.start(starting_port_number++);
    for (int i = 0; i < 1000; ++i)
      test_connect_then_io_stop(port);
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

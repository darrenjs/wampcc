#include "test_common.h"

#include <wampcc/tcp_socket.h>
#include <wampcc/io_loop.h>

#include <stdexcept>

using namespace wampcc;
using namespace std;


void test_passive_disconnect(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";

  socket_listener the_socket_reader;

  internal_server iserver;
  iserver.start(port);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  tcp_socket sock( the_kernel.get() );

  auto fut = sock.connect("127.0.0.1", port);

  std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

  if (status != std::future_status::ready)
  {
    cout << "result not ready ... waiting\n";
    fut.wait();
  }

  fut.get();

  if (sock.is_connected() == false)
    throw runtime_error("expected to be connected");

  the_socket_reader.start_listening(sock);

  iserver.reset_dealer();


  // kernel is reset before the local socket is closed
  the_kernel.reset();
}




void test_passive_disconnect_then_client_sock_close(int port)
{
  cout << "---------- " << __FUNCTION__ << " ----------\n";

  socket_listener the_socket_reader;

  internal_server iserver;
  iserver.start(port);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  tcp_socket sock( the_kernel.get() );

  auto fut = sock.connect("127.0.0.1", port);

  std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

  if (status != std::future_status::ready)
  {
    cout << "result not ready ... waiting\n";
    fut.wait();
  }

  fut.get();

  if (sock.is_connected() == false)
    throw runtime_error("expected to be connected");

  the_socket_reader.start_listening(sock);


  iserver.reset_dealer();

  // close socket before kernel is reset
  sock.close();
  sock.closed_future().wait();

  the_kernel.reset();
}









int main(int argc, char** argv)
{
  int starting_port_number = 23100;
  int port;

  if (argc>1)
    starting_port_number = atoi(argv[1]);

  port = starting_port_number++;

  auto all_tests = [&port]()
  {
    test_passive_disconnect(port++);
    test_passive_disconnect_then_client_sock_close(port++);
  };

  {
    all_tests();
  }

  {
    for (int i = 0; i < 1000; i++)
      all_tests();
  }


  cout << "tests complete\n";

  return 0;
}

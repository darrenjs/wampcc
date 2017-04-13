/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

#include "wampcc/tcp_socket.h"

#include <stdexcept>

using namespace wampcc;
using namespace std;


void test_unused_socket()
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  tcp_socket sock( the_kernel.get() );
}


void test_address(string node, string port, tcp_socket::addr_family af, bool expected)
{
  TSTART();

  kernel the_kernel;

  tcp_socket::on_accept_cb on_accept = [](unique_ptr<tcp_socket>& client,
                                          uverr status) {};

  tcp_socket sever_sock(&the_kernel);

  std::future<uverr> fut = sever_sock.listen(node, port, on_accept, af);
  fut.wait();

  uverr ec = fut.get();

  if (expected == (ec == 0))
    return;
  else
    throw std::runtime_error("unexpected");
}


void test_address_combinations(int port)
{
  string portstr = to_string(port);
  test_address("0.0.0.0",   portstr, tcp_socket::addr_family::inet4, true);
  test_address("127.0.0.1", portstr, tcp_socket::addr_family::inet4, true);
  test_address("127.255.255.254", portstr, tcp_socket::addr_family::inet4, true);
  test_address("0.0.0.0",   portstr, tcp_socket::addr_family::inet6, false);
  test_address("127.0.0.1", portstr, tcp_socket::addr_family::inet6, false);

  test_address("::1", portstr, tcp_socket::addr_family::inet6, true);
  test_address("::1", portstr, tcp_socket::addr_family::inet4, false);

  test_address("", portstr, tcp_socket::addr_family::inet4, true);
  test_address("", portstr, tcp_socket::addr_family::inet6, true);
  test_address("", portstr, tcp_socket::addr_family::unspec, true);
}


void test_listen_node_port(string node, int port)
{
  TSTART();

  kernel the_kernel;

  tcp_socket::on_accept_cb on_accept = [](unique_ptr<tcp_socket>& client,
                                          uverr status) {};

  {
    tcp_socket sever_sock(&the_kernel);

    string portstr = std::to_string(port);

    std::future<uverr> fut = sever_sock.listen(node, portstr, on_accept, tcp_socket::addr_family::inet4);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting longer\n";
      fut.wait();
    }

    uverr result = fut.get();
    if (result == 0)
    {
      assert(sever_sock.is_listening() == true);
      assert(sever_sock.is_connected() == false);
     }
    else
    {
      assert(sever_sock.is_listening() == false);
      assert(sever_sock.is_connected() == false);
      cout << "socket failed to listen, status: " << result << endl;
    }
    sever_sock.close().wait();
  }
}


void test_canonical_listen(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  unique_ptr<tcp_socket> accepted_socket;
  tcp_socket::on_accept_cb on_accept = [&accepted_socket](unique_ptr<tcp_socket>& client,
                                                          uverr status)
  {
    if (status==0)
    {
      cout << "accepted connect request" << endl;

      assert( (bool)client == true);
      accepted_socket = std::move(client);
      assert(accepted_socket->is_connected() == true);
    }
    else
      cout << "accept failed, status " << status << endl;
  };

  {
    tcp_socket sever_sock( the_kernel.get() );

    std::future<uverr> fut = sever_sock.listen("", std::to_string(port), on_accept);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting longer\n";
      fut.wait();
    }

    uverr result = fut.get();
    if (result == 0)
    {
      assert(sever_sock.is_listening() == true);
      assert(sever_sock.is_connected() == false);

      cout << "client attempting to connect..." << endl;
      tcp_socket client_sock(the_kernel.get());
      client_sock.connect("127.0.0.1", port).wait();
      cout << "client connected: " << client_sock.is_connected() << endl;
    }
    else
    {
      assert(sever_sock.is_listening() == false);
      assert(sever_sock.is_connected() == false);
      cout << "socket failed to listen, status: " << result << endl;
    }
  }
}


void test_listen_duplicate_port(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  auto on_accept = [](unique_ptr<tcp_socket>& client,
                      uverr status)
  {
    assert(strlen("on accept should not happen for a failed socket")==0);
  };

  {

    tcp_socket sever_sock_first( the_kernel.get() );
    sever_sock_first.listen("", std::to_string(port), [](std::unique_ptr<tcp_socket>&,uverr){}).wait();
    if (!sever_sock_first.is_listening())
    {
      cout << "unable to get port" << endl;
      return;
    }

    tcp_socket sever_sock( the_kernel.get() );

    std::future<uverr> fut = sever_sock.listen("", std::to_string(port), on_accept);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting longer\n";
      fut.wait();
    }

    uverr result = fut.get();
    cout << "listen status: " << result << endl;
    assert(result != 0);
  }
}



void test_listen_close(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  auto on_accept = [](unique_ptr<tcp_socket>& client,
                      uverr status)
  {
    assert(strlen("on accept should not happen for a failed socket")==0);
  };

  {
    tcp_socket sever_sock( the_kernel.get() );

    sever_sock.listen("", std::to_string(port), on_accept).wait();
    if (!sever_sock.is_listening())
    {
      cout << "unable to listen" << endl;
      return;
    }

    cout << "calling close" << endl;
    sever_sock.close().wait();
  }
}


/* Test that a new client can be received on the on_accept callback, but not be
 * used. The socket will thus need to be deleted on the IO thread, which is
 * something that can result in immediate deadlock.
 */
void test_unused_client(int port)
{
  TSTART();

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));

  auto on_accept = [](unique_ptr<tcp_socket>&,
                      uverr status)
  {
  };

  {
    tcp_socket sever_sock( the_kernel.get() );

    std::future<uverr> fut = sever_sock.listen("", std::to_string(port), on_accept);
    std::future_status status = fut.wait_for(std::chrono::milliseconds(100));

    if (status != std::future_status::ready)
    {
      cout << "result not ready ... waiting longer" << endl;
      fut.wait();
    }

    uverr result = fut.get();
    if (result == 0)
    {
      cout << "client attempting to connect..." << endl;
      tcp_socket client_sock(the_kernel.get());
      client_sock.connect("127.0.0.1", port).wait();
      cout << "client connected: " << client_sock.is_connected() << endl;
    }
    else
    {
      assert(sever_sock.is_listening() == false);
      assert(sever_sock.is_connected() == false);
      cout << "socket failed to listen, status: " << result << endl;
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
    test_canonical_listen(port);
    test_listen_duplicate_port(port);
    test_listen_close(port);
    test_unused_client(port);
    test_listen_node_port("",port);
    test_listen_node_port("127.0.0.1",port);
    test_listen_node_port("0.0.0.0",port);
  };


  port = starting_port_number++;
  test_address_combinations(port);

  {
    port = starting_port_number++;
    all_tests(port);
  }

  {
    port = starting_port_number++;

    for (int i = 0; i < 500; i++)
      all_tests(port);
  }

  {
    port = starting_port_number++;
    for (int i = 0; i < 500; i++)
      test_unused_client(port);
  }

  return 0;
}

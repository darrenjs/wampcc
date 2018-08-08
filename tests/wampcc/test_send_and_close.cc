/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

/* Test that a sender can send many messages on a wamp session, followed
 * immediately by a close, and confirm that the receiver will receive all the
 * messages sent.
 */

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 500;

std::string uri_numbers_topic = "numbers";

#define LOG(LOGGER, X)                                                   \
  do {                                                                  \
    auto level = wampcc::logger::eInfo;                                 \
    if (LOGGER.wants_level && LOGGER.write && LOGGER.wants_level(level)) { \
      std::ostringstream __xx_oss;                                      \
      __xx_oss << X;                                                    \
      LOGGER.write(level, __xx_oss.str(), __FILE__, __LINE__);          \
    }                                                                   \
  } while (0)


TEST_CASE("test_send_batch_then_close")
{
/*
  Test we can send a lot of messages, followed by a graceful closure, and that
  all the messages in fact do arrive at the destination.  I.e., the receiver
  should first see the messages, and then followed by seeing the session close
  event.

  To simulate this, we slow down the receiver so that it has a brief sleep
  during the event callback.  This should allow sufficient time for the sender
  to have sent all the messages and closed the session.
 */

  auto logger = logger::console();
  //auto logger = debug_logger();

  internal_server server(logger);
  int port = server.start(global_port++);

  constexpr size_t data_size = 20;
  constexpr int delay_ms = 100;

  // data to send from sender to receiver; test is to check if all of the data
  // arrives
  std::vector<json_array> data_sent(data_size);
  for (size_t i = 0; i<data_size; i++)
    data_sent[i].push_back( wampcc::json_value::make_uint(i) );

  std::mutex data_recv_mutex;
  std::condition_variable data_recv_condvar;

  std::vector<json_array> data_recv;


  server.router()->callable("default_realm", uri_numbers_topic,
                                [&](wampcc::wamp_router&,
                                    wampcc::wamp_session&,
                                    wampcc::call_info info) {
                                  this_thread::sleep_for(chrono::milliseconds(delay_ms));
                                  {
                                    std::lock_guard<std::mutex> guard(data_recv_mutex);
                                    data_recv.push_back(info.args.args_list);

                                    if (data_recv.size() == data_size)
                                      data_recv_condvar.notify_one();
                                  }
                                  //invoc.yield(invoc.args.args_list);
                                });
  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger));
    auto session = establish_session(the_kernel, port, (int)protocol_type::rawsocket);

    INFO("sender session created with unique id #" << session->unique_id());
    perform_realm_logon(session);

    wampcc::json_object options;
    wampcc::wamp_args args;
    args.args_list.push_back(wampcc::json_value::make_uint(0));

    for (size_t i = 0; i < data_size; i++) {
      args.args_list = data_sent[i];
      session->call(uri_numbers_topic, {}, args, [&](wampcc::wamp_session&,
                                                     wampcc::result_info r) {
        });
    }

    // immediately close -- test is to see if router still handles the
    // messages sent

    if (session->close().wait_for(std::chrono::seconds(1)) != std::future_status::ready)
      throw std::runtime_error("timeout during session close");

    INFO("sender session has been closed, #" << session->unique_id());
  }

  INFO("waiting for test to complete...");
  {
    std::unique_lock<std::mutex> guard(data_recv_mutex);
    auto max_interval = chrono::milliseconds(delay_ms * data_size * 5);
    data_recv_condvar.wait_for(guard, max_interval,
                               [&]()->bool {return data_recv.size() == data_size;});
  }

  INFO("items sent: " << data_sent.size());
  INFO("items recv: " << data_recv.size());

  // This sleep is needed to allow the router.provide callback to complete.
  // Without this, when the callback raises the condition variable, the outer
  // thread waiting on the condition can continue and possible exit the function
  // (via exception thrown on the test case).  If it does that very quickly, the
  // thread still in the callback will be attempting to use a mutex this is no
  // longer on the stack.
  this_thread::sleep_for(chrono::milliseconds(500));

  REQUIRE(data_sent == data_recv);
}

int main(int argc, char** argv)
{
  try
  {
    global_port = 27000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return result < 0xFF ? result : 0xFF;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }
}

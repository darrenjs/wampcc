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


TEST_CASE("test_send_no_reply")
{

  //internal_server server(logger::console());
  internal_server server(debug_logger());
  int port = server.start(global_port++);

  // /* create some unused sessions, to bump the session id higher, so can easily
  //  * see which session is which in log output*/
  // {
  //   unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  //   for (int i = 0; i < 10; i++)
  //     auto session = establish_session(the_kernel, port);
  // }

  constexpr int data_size = 20;

  // data to send from sender to receiver; test is to check if all of the data
  // arrives
  std::vector<json_array> data_sent(data_size);
  for (int i = 0; i<data_size; i++)
    data_sent[i].push_back( wampcc::json_value::make_uint(i) );

  std::vector<json_array> data_recv;

  server.router()->provide("default_realm", uri_numbers_topic, {},
                           [&data_recv](wampcc::wamp_invocation& invoc) {
                             std::cout << "request: " << invoc.args.args_list << std::endl;
                             data_recv.push_back(invoc.args.args_list);
                             //invoc.yield(invoc.args.args_list);
                           });

  // TODO: create a session
  //auto logger = logger::console();
  auto logger = debug_logger();

  unique_ptr<kernel> the_kernel(new kernel({}, logger));
  auto session = establish_session(the_kernel, port, (int)protocol_type::websocket);

  std::cout << "sender session created with unique id #" << session->unique_id() << std::endl;
  perform_realm_logon(session);

  // TODO: on session, publish lots of messages

  wampcc::json_object options;
  wampcc::wamp_args args;
  args.args_list.push_back(wampcc::json_value::make_uint(0));

  for (int i = 0; i < data_size; i++) {
    args.args_list = data_sent[i];
    session->call(uri_numbers_topic, {}, args, [&](wampcc::wamp_call_result r) {
        std::cout << "reply: " << r.args.args_list << std::endl;
      });
  }

  //this_thread::sleep_for(chrono::milliseconds(100));

  // immediately close -- test is to see if router still handles the
  // messages sent

  session->close().wait();

  LOG(logger,  "*** sender session has been closed, #" << session->unique_id() );
  std::cout << "item sent: " << data_sent.size() << std::endl;
  std::cout << "item recv: " << data_recv.size() << std::endl;
  assert(data_sent == data_recv);
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

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

using namespace wampcc;

int global_port;
int global_loops = 50;

/* Perform basic RPC test using range of protocols supported by wampcc. */

std::vector<protocol_type> protocols{protocol_type::websocket,
                                     protocol_type::rawsocket};

std::vector<serialiser_type> serialisers{serialiser_type::json,
                                         serialiser_type::msgpack};

std::string protocol_str(protocol_type p)
{
  switch(p) {
    case protocol_type::none : return "none";
    case protocol_type::websocket : return "websocket";
    case protocol_type::rawsocket : return "rawsocket";
  }
  return "unknown";
}
std::string serialiser_str(serialiser_type p)
{
  switch(p) {
    case serialiser_type::none : return "none";
    case serialiser_type::json : return "json";
    case serialiser_type::msgpack : return "msgpack";
  }
  return "unknown";
}


std::shared_ptr<internal_server> create_server(
    int& port, int allowed_protocols = wampcc::all_protocols,
    int allowed_serialisers = wampcc::all_serialisers)
{
  std::shared_ptr<internal_server> iserver(new internal_server());

  port = iserver->start(port, allowed_protocols, allowed_serialisers);

  if (port) {
    iserver->router()->provide("default_realm", "math.add", {},
                               [](wamp_invocation& invoke) {
      int total = 0;
      for (auto& item : invoke.args.args_list)
        if (item.is_int())
          total += item.as_int();
      invoke.yield({total});
    });
  }

  return iserver;
}


void run_rpc_test(std::shared_ptr<internal_server>& server,
                  protocol_type client_protocol,
                  serialiser_type client_serialiser, bool expect_success)
{
  std::ostringstream oss;
  oss << __FUNCTION__ << ", protocol:" << protocol_str(client_protocol)
      << ", serialiser:" << serialiser_str(client_serialiser)
      << ", expect: " << expect_success << std::endl;
  bool actual_result = false;

  // create the client
  std::unique_ptr<kernel> the_kernel(new kernel());

  try {
    auto session = establish_session(the_kernel, server->port(),
                                     static_cast<int>(client_protocol),
                                     static_cast<int>(client_serialiser));
    perform_realm_logon(session);

    wamp_args call_args;
    call_args.args_list = json_array({1,2,3,4,5});

    wamp_call_result result = sync_rpc_all(session, "math.add", call_args,
                                           rpc_result_expect::success);

    int value = result.args.args_list[0].as_int();

    session->close().wait();

    if (value == 15)
      actual_result = true;
  } catch (std::exception& e) {
    if (expect_success)
      std::cout << "exception: " << e.what() << std::endl;
  }

  if (actual_result && !expect_success)
    throw std::runtime_error("run_rpc_test passed but expected fail: " + oss.str());
  if (!actual_result && expect_success)
    throw std::runtime_error("run_rpc_test failed but expected pass:" + oss.str());
}


void run_tests_against_null_server(int& port)
{
  /* create range of servers which have no protocol / serialiser */
  std::vector<std::shared_ptr<internal_server>> servers{
      create_server(port, 0, 0),
      create_server(port, 0, wampcc::all_serialisers),
      create_server(port, wampcc::all_protocols, 0)};

  /* these should all fail */
  for (auto& svr : servers)
    for (auto pt : protocols)
      for (auto st : serialisers)
        run_rpc_test(svr, pt, st, false);
}

TEST_CASE("run_tests_against_null_server")
{
  /* create a generic server that will support all protocols and serialisers */
  run_tests_against_null_server(++global_port);
}

void run_compatible_protocol_tests(int& port)
{
  /* These tests check that an incompatible server & client protocol will
   * fail, and compatible servers are successful. */

  {
    auto server = create_server(++port, (int)protocol_type::websocket);
    for (auto st : serialisers) {
      run_rpc_test(server, protocol_type::websocket, st, true);
      run_rpc_test(server, protocol_type::rawsocket, st, false);
    }
  }

  {
    auto server = create_server(++port, (int)protocol_type::rawsocket);
    for (auto st : serialisers) {
      run_rpc_test(server, protocol_type::websocket, st, false);
      run_rpc_test(server, protocol_type::rawsocket, st, true);
    }
  }
}

TEST_CASE("run_compatible_protocol_tests")
{
  /* create a generic server that will support all protocols and serialisers */
  run_compatible_protocol_tests(++global_port);
}


TEST_CASE("basic_generic_server")
{
  /* create a generic server that will support all protocols and serialisers */
  auto generic_server = create_server(++global_port);

  for (auto pt : protocols)
    run_rpc_test(generic_server, pt, serialiser_type::json, true);

  for (auto pt : protocols)
    run_rpc_test(generic_server, pt, serialiser_type::msgpack, true);
}

int main(int argc, char** argv)
{
  try {
    global_port = 25000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return (result < 0xFF ? result : 0xFF );
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

#include "mini_test.h"

using namespace wampcc;
using namespace std;

int global_port;
int global_loops = 50;

void test_registration_failure_empty_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  std::promise<std::pair<bool, std::string>> promised_result;

  wampcc::on_registered_fn on_result =
    [&promised_result](wamp_session&, registered_info info) {
    promised_result.set_value({!info.was_error,std::move(info.error_uri)});
  };

  session->provide(
    "", {},   // Empty name
    on_result,
    [](wamp_session& ws, invocation_info info){
      ws.yield(info.request_id);
    }
    );

  auto result = promised_result.get_future().get();

  assert(result.first == false);
}

TEST_CASE("test_registration_failure_empty_uri")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_registration_failure_empty_uri(port, iserver);
}

void test_registration_failure_bad_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  std::promise<std::pair<bool, std::string>> promised_result;

  wampcc::on_registered_fn on_result =
    [&promised_result](wamp_session&, registered_info info) {
    promised_result.set_value({!info.was_error,std::move(info.error_uri)});
  };

  session->provide(
    " . . . . .", {},   // Bad name
    on_result,
    [](wamp_session& ws, invocation_info info){
      ws.yield(info.request_id);
    }
    );

  auto result = promised_result.get_future().get();

  assert(result.first == false);
}


TEST_CASE("test_registration_failure_bad_uri")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_registration_failure_bad_uri(port, iserver);
}


void test_registration_duplicate_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);


  // register the procedure
  {
    std::promise<std::pair<bool, std::string>> promised_result;

    wampcc::on_registered_fn on_result =
      [&promised_result](wamp_session&, registered_info info) {
      promised_result.set_value({!info.was_error,std::move(info.error_uri)});
    };

    session->provide(
      "api.test", {},
      on_result,
      [](wamp_session& ws, invocation_info info){
        ws.yield(info.request_id);
      }
      );

    auto result = promised_result.get_future().get();

    assert(result.first == true);
  }

  // attempt to register a second time ... should fail
  {
    std::promise<std::pair<bool, std::string>> promised_result;

    wampcc::on_registered_fn on_result =
      [&promised_result](wamp_session&, registered_info info) {
      promised_result.set_value({!info.was_error,std::move(info.error_uri)});
    };

    session->provide(
      "api.test", {},
      on_result,
      [](wamp_session& ws, invocation_info info){
        ws.yield(info.request_id);
      }
      );

    auto result = promised_result.get_future().get();
    assert(result.second == WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    assert(result.first == false);
  }
}


TEST_CASE("test_registration_duplicate_uri")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_registration_duplicate_uri(port, iserver);
}


auto all_tests = [](int port, internal_server& server)
{
  test_registration_failure_empty_uri(port, server);
  test_registration_failure_bad_uri(port, server);
  test_registration_duplicate_uri(port, server);
};


TEST_CASE("test_all")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  all_tests(port, iserver);
}


TEST_CASE("test_all_bulk_v1")
{
  for (int i = 0; i < 50; i++)
  {
    internal_server iserver;
    int port = iserver.start(global_port++);
    all_tests(port, iserver);
  }
}


TEST_CASE("test_all_bulk_v2")
{
  internal_server iserver;
  int port = iserver.start(global_port++);

  for (int i = 0; i < 50; i++)
    all_tests(port, iserver);
}


int main(int argc, char** argv)
{
  try {
    global_port = 25000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return (result < 0xFF ? result : 0xFF);
  } catch (exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

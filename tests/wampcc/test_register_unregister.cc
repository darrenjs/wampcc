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
//int global_loops = 50;


TEST_CASE("test_unregister")
{
  const std::string uri = "my_rpc";
  internal_server iserver(logger::nolog());
  int port = iserver.start(global_port++);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  t_registration_id registration_id = 0;

  // register the procedure
  {
    std::promise<int> promised_registration_id;
    session->provide(
      uri, {},
      [&promised_registration_id](wamp_session&, registered_info info) {
        promised_registration_id.set_value(info.registration_id);
      },
      [](wamp_session& ws, invocation_info info) {
        ws.yield(info.request_id);
      },
      nullptr
      );

    registration_id = promised_registration_id.get_future().get();
    //INFO( "registered, with registration_id " << registration_id);
  }

  // check that the procedure can be called
  {
    std::promise<result_info> promised_result_info;

    session->call(uri, {}, {},
                  [&promised_result_info](wamp_session&, result_info info){
                    promised_result_info.set_value(std::move(info));
                  }, nullptr
      );

    auto future_result_info = promised_result_info.get_future();

    REQUIRE(future_result_info.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_result_info = future_result_info.get();
    REQUIRE(result_result_info.was_error == false);
  }

  // check that second registration fails
  {
    std::promise<registered_info> promised_registered_info;
    session->provide(
      uri, {},
      [&promised_registered_info](wamp_session&, registered_info info) {
        promised_registered_info.set_value(info);
      },
      [](wamp_session& ws, invocation_info info) {
        ws.yield(info.request_id);
      },
      nullptr
      );

    auto fut = promised_registered_info.get_future();

    REQUIRE(fut.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_registered_info = fut.get();
    REQUIRE(result_registered_info.was_error == true);
  }

  // unregister
  {
    std::promise<unregistered_info> promised_unregistered_info;

    session->unprovide(
      registration_id,
      [&promised_unregistered_info](wamp_session&, unregistered_info info) {
        promised_unregistered_info.set_value(std::move(info));
      },
      nullptr
      );

    auto future_unregistered_info = promised_unregistered_info.get_future();

    REQUIRE(future_unregistered_info.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_unregistered_info = future_unregistered_info.get();
    REQUIRE(result_unregistered_info.was_error == false);
  }

  // check that the procedure can be called (should fail)
  {
    std::promise<result_info> promised_result_info;

    session->call(
      uri, {}, {},
      [&promised_result_info](wamp_session&, result_info info){
        promised_result_info.set_value(std::move(info));
      }, nullptr
      );

    auto future_result_info = promised_result_info.get_future();

    REQUIRE(future_result_info.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_result_info = future_result_info.get();
    REQUIRE(result_result_info.was_error == true); // expected to fail
  }

  // check registration works again
  {
    std::promise<registered_info> promised_registration_id;
    session->provide(
      uri, {},
      [&promised_registration_id](wamp_session&, registered_info info) {
        promised_registration_id.set_value(info);
      },
      [](wamp_session& ws, invocation_info info) {
        ws.yield(info.request_id);
      },
      nullptr
      );

    auto fut = promised_registration_id.get_future();

    REQUIRE(fut.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_registered_info = fut.get();
    REQUIRE(result_registered_info.was_error == false);

    // We expect that the new registration id is different from the previous
    // value
    REQUIRE(result_registered_info.registration_id != registration_id);

    //INFO("registered, with registration_id " << result_registered_info.registration_id);
  }

  // check that the procedure can be called
  {
    std::promise<result_info> promised_result_info;

    session->call(uri, {}, {},
                  [&promised_result_info](wamp_session&, result_info info){
                    promised_result_info.set_value(std::move(info));
                  }, nullptr
      );

    auto future_result_info = promised_result_info.get_future();

    REQUIRE(future_result_info.wait_for(
              std::chrono::seconds(3)) == std::future_status::ready);

    auto result_result_info = future_result_info.get();
    REQUIRE(result_result_info.was_error == false);
  }
}

TEST_CASE("test_unregister_router") {
  const std::string uri = "my_rpc";
  const std::string realm = "default_realm";
  internal_server iserver(logger::nolog());
  int port = iserver.start(global_port++);

  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  auto registration_id = iserver.router()->callable(realm, uri,
      [](wampcc::wamp_router& rtr, wampcc::wamp_session& caller, wampcc::call_info info) {
          caller.result(info.request_id, {"hello"});
      }, nullptr);

  std::promise<result_info> promised_result_info;

  session->call(uri, {}, {},
      [&promised_result_info](wamp_session&, result_info info) {
        promised_result_info.set_value(std::move(info));
      },
      nullptr);

  auto future_result_info = promised_result_info.get_future();

  REQUIRE(future_result_info.wait_for(std::chrono::seconds(3)) ==
          std::future_status::ready);

  REQUIRE(future_result_info.get().was_error == false);

  // check that second registration fails
  std::string error_uri;
  try {
    iserver.router()->callable(realm, uri,
        [](wampcc::wamp_router&, wampcc::wamp_session&, wampcc::call_info) {},
        nullptr);
  }
  catch (const wampcc::wamp_error& error) {
    error_uri = error.error_uri();
  }
  REQUIRE(error_uri == WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);

  // check that incorrect unregister fails
  try {
    iserver.router()->unregister_callable(realm, registration_id + 1);
  }
  catch (const wampcc::wamp_error& error) {
    error_uri = error.error_uri();
  }
  REQUIRE(error_uri == WAMP_ERROR_NO_SUCH_REGISTRATION);

  // unregister
  iserver.router()->unregister_callable(realm, registration_id);

  // check that the procedure can no longer be called
  promised_result_info = {};
  session->call(uri, {}, {},
      [&promised_result_info](wamp_session&, result_info info) {
        promised_result_info.set_value(std::move(info));
      },
      nullptr);

  future_result_info = promised_result_info.get_future();

  REQUIRE(future_result_info.wait_for(std::chrono::seconds(3)) ==
          std::future_status::ready);

  REQUIRE(future_result_info.get().was_error == true);
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

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

using namespace wampcc;
using namespace std;

void test_registration_failure_empty_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  std::promise<std::pair<bool, std::string>> promised_result;
  wampcc::result_cb on_result = [&promised_result](bool is_good,
                                                  std::string error_uri) {
    promised_result.set_value({is_good,std::move(error_uri)});
  };

  session->provide(
    "", {},   // Empty name
    on_result,
    [](wamp_invocation& invoke){
      invoke.yield();
    }
    );

  auto result = promised_result.get_future().get();

  assert(result.first == false);
}


void test_registration_failure_bad_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);

  std::promise<std::pair<bool, std::string>> promised_result;
  wampcc::result_cb on_result = [&promised_result](bool is_good,
                                                  std::string error_uri) {
    promised_result.set_value({is_good,std::move(error_uri)});
  };

  session->provide(
    " . . . . .", {},   // Bad name
    on_result,
    [](wamp_invocation& invoke){
      invoke.yield();
    }
    );

  auto result = promised_result.get_future().get();

  assert(result.first == false);
}


void test_registration_duplicate_uri(int port, internal_server& server)
{
  unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
  auto session = establish_session(the_kernel, port);
  perform_realm_logon(session);


  // register the procedure
  {
    std::promise<std::pair<bool, std::string>> promised_result;
    wampcc::result_cb on_result = [&promised_result](bool is_good,
                                                     std::string error_uri) {
      promised_result.set_value({is_good,std::move(error_uri)});
    };

    session->provide(
      "api.test", {},
      on_result,
      [](wamp_invocation& invoke){
        invoke.yield();
      }
      );

    auto result = promised_result.get_future().get();

    assert(result.first == true);
  }

  // attempt to register a second time ... should fail
  {
    std::promise<std::pair<bool, std::string>> promised_result;
    wampcc::result_cb on_result = [&promised_result](bool is_good,
                                                     std::string error_uri) {
      promised_result.set_value({is_good,std::move(error_uri)});
    };

    session->provide(
      "api.test", {},
      on_result,
      [](wamp_invocation& invoke){
        invoke.yield();
      }
      );

    auto result = promised_result.get_future().get();
    assert(result.second == WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    assert(result.first == false);
  }
}


int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 25000;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    auto all_tests = [](int port, internal_server& server)
      {
        test_registration_failure_empty_uri(port, server);
        test_registration_failure_bad_uri(port, server);
        test_registration_duplicate_uri(port, server);
      };

    // one-off test
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port, iserver);
    }

    // share a common internal_server
    for (int i = 0; i < 50; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port, iserver);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}

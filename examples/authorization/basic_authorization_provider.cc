/*
 * Copyright (c) 2017 Darren Smith
 * Copyright (c) 2018 Daniel Kesler
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <iostream>

using namespace wampcc;
using namespace std;

int main(int, char**)
{
  try {
    /* Create the wampcc kernel. */

    kernel the_kernel;

    /* Create an embedded wamp router. */

    wamp_router router(&the_kernel);

    /* Accept clients on IPv4 port, without authentication. */

    auth_provider auth = {
      // provider_name
      [](const std::string& realm) { 
        return "example_auth"; 
      },
      // policy
      [](const std::string& user, const std::string& realm) {
        if(realm == "default_realm")
          return auth_provider::auth_plan{ auth_provider::mode::open, {} };
        else if(realm == "private_realm")
          return auth_provider::auth_plan(auth_provider::mode::authenticate, {"wampcra"});
        else
          return auth_provider::auth_plan(auth_provider::mode::forbidden, {});
      },
      // cra_salt
      nullptr, 
      // check_cra
      nullptr, 
      // user_secret
      [](const std::string& /*user*/, const std::string& /*realm*/) {
        return "secret2"; 
      },

      /* Authorization provider */

      // user_role
      [](const std::string& user, const std::string& realm) {
        std::string role = "anonymous";

        if(realm == "private_realm") {
          if(user == "peter")
            role = "member";
          else if(user == "tony")
            role = "admin";
        }

        std::cout << "(" << user << ", " << realm << ") => " << role << std::endl;

        return role;
      },
      // authorize
      [](const std::string& realm, const std::string& authrole, const std::string& uri, auth_provider::action) {
        if(uri == "admin.greeting" && authrole == "admin") {
          return true;
        } else if (uri == "greeting") {
          return true;
        }
        return false;
      }
    };

    auto fut = router.listen(auth, 55555);

    if (auto ec = fut.get())
      throw runtime_error(ec.message());

    /* Provide an RPC named 'greeting' on realm 'default_realm'. */

    router.callable("default_realm", "greeting",
                    [](wamp_router&, wamp_session& caller, call_info info) {
      caller.result(info.request_id, {"hello"});
    });

    router.callable("private_realm", "greeting",
                    [](wamp_router&, wamp_session& caller, call_info info) {
      caller.result(info.request_id, {"hello, private member"});
    });

    router.callable("private_realm", "admin.greeting",
                    [](wamp_router&, wamp_session& caller, call_info info) {
      caller.result(info.request_id, {"hello, admin"});
    });

    /* Suspend main thread */
    std::promise<void> forever;
    forever.get_future().wait();
  } catch (const exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

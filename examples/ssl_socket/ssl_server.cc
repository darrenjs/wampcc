/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

using namespace wampcc;
using namespace std;

/* Called on the kernel's IO thread when the server socket has accepted a new
 * client socket. */
void on_ssl_accept(std::unique_ptr<ssl_socket>& client, uverr ec)
{
  // TODO: take ownership of socket

  // TODO: start read
}


int main(int, char**)
{
  try {
    /* Create the wampcc kernel, configured to support SSL. */

    config conf;
    conf.ssl.enable = true;
    conf.ssl.certificate_file="server.crt";
    conf.ssl.private_key_file="server.key";
    kernel the_kernel(conf, logger::stdout());

    /* Create an SSL socket, which will operate in server mode, via the call to
     * listen. */

    ssl_socket ssl_server(&the_kernel);

    auto err = ssl_server.listen("", "55555", on_ssl_accept,
                                 tcp_socket::addr_family::inet4);

    /* Suspend main thread */

    pause();
  } catch (const exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

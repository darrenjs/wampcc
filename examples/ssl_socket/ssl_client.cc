/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

using namespace wampcc;

int main(int argc, char** argv)
{
  try {
    if (argc < 3)
      throw std::runtime_error("arguments must be: ADDR PORT");

    /* Create the wampcc kernel, configured to support SSL. */
    config conf;
    conf.ssl.enable = true;
    kernel the_kernel(conf, logger::console());

    /* Create the SSL socket, in connector mode. */
    ssl_socket sock(&the_kernel);

    /* Attempt to connect to peer, and wait for success/failure. */
    if (auto err = sock.connect(argv[1], atoi(argv[2])).get())
      throw std::runtime_error(err.message());

    /* Important! Before doing anything with the SSL socket, we must enable it
     * for read operations, otherwise it will be unable to complete the SSL
     * handshake. */
    sock.start_read([](char* src, size_t n) {
                      std::cout << "on_read: [" << std::string(src, n) << "]"
                                << std::endl;
                    },
                    [&](uverr e) {
                      std::cout << "on_error: " << e << std::endl;
                      sock.close();
                    });

    /* Optionally initiate SSL handshake. If not done explicity, it is
     * automatically called when data is first written. */
    if (sock.handshake().get() != ssl_socket::t_handshake_state::success)
      throw std::runtime_error("SSL handshake failed");

    /* Echo stdin to the SSL socket, except 'X' which breaks loop. */
    for (std::string line; std::getline(std::cin, line) && line != "X";)
      sock.write(line.c_str(), line.size());

    /* Close the socket object and wait until complete. */
    sock.close().wait();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

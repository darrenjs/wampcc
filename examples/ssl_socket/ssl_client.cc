/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

using namespace wampcc;
using namespace std;

int main(int, char**)
{
  try {

    /* Create the wampcc kernel. */
    kernel the_kernel;

    ssl_socket server_socket(&the_kernel);

    /* Suspend main thread */
    pause();
  } catch (const exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_VERSION_H
#define WAMPCC_VERSION_H

#define WAMPCC_PACKAGE_NAME "wampcc"
#define WAMPCC_PACKAGE_VERSION "1.6"
#define WAMPCC_PACKAGE_STRING "wampcc 1.6"

#define WAMPCC_MAJOR_VERSION 1
#define WAMPCC_MINOR_VERSION 6
#define WAMPCC_MICRO_VERSION 0

namespace wampcc {

/* Below are functions to inspect the versions of libuv used at wampcc
 * compile-time and application run-time. These can be used if an application
 * wants to check whether the same version was used for both compile and link.
 */

/* Obtain the version numbers of the libuv library used when compiling wampcc */
void libuv_version_wampcc_compiletime(int& major, int &minor);

/* Obtain the version numbers of the libuv library found at runtime */
void libuv_version_runtime(int& major, int &minor);

}

#endif

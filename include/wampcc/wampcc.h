/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_H
#define WAMPCC_H

#ifndef _WIN32
#  if __cplusplus < 201103L
#    error "C++11 required"
#  endif
#endif

/* Convenience header to include all public wampcc headers */

#include "wampcc/data_model.h"
#include "wampcc/error.h"
#include "wampcc/helper.h"
#include "wampcc/json.h"
#include "wampcc/kernel.h"
#include "wampcc/protocol.h"
#include "wampcc/rawsocket_protocol.h"
#include "wampcc/socket_address.h"
#include "wampcc/ssl_socket.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/types.h"
#include "wampcc/wamp_router.h"
#include "wampcc/wamp_session.h"
#include "wampcc/websocket_protocol.h"

#endif

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_WAMPTYPES_H
#define WAMPCC_WAMPTYPES_H

#include "wampcc/json.h"

#include <functional>
#include <mutex>
#include <string>
#include <memory>
#include <stdint.h>

namespace wampcc
{

// WAMP defined error messages
#define WAMP_ERROR_AUTHORIZATION_FAILED "wamp.error.authorization_failed"
#define WAMP_ERROR_CANCELED "wamp.error.canceled"
#define WAMP_ERROR_CLOSE_REALM "wamp.error.close_realm"
#define WAMP_ERROR_GOODBYE_AND_OUT "wamp.error.goodbye_and_out"
#define WAMP_ERROR_INVALID_ARGUMENT "wamp.error.invalid_argument"
#define WAMP_ERROR_INVALID_URI "wamp.error.invalid_uri"
#define WAMP_ERROR_NETWORK_FAILURE "wamp.error.network_failure"
#define WAMP_ERROR_NOT_AUTHORIZED "wamp.error.not_authorized"
#define WAMP_ERROR_NO_ELIGIBLE_CALLEE "wamp.error.no_eligible_callee"
#define WAMP_ERROR_NO_SUCH_REALM "wamp.error.no_such_realm"
#define WAMP_ERROR_NO_SUCH_ROLE "wamp.error.no_such_role"
#define WAMP_ERROR_NO_SUCH_SUBSCRIPTION "wamp.error.no_such_subscription"
#define WAMP_ERROR_OPTION_NOT_ALLOWED "wamp.error.option_not_allowed"
#define WAMP_ERROR_PROCEDURE_ALREADY_EXISTS "wamp.error.procedure_already_exists"
#define WAMP_ERROR_SYSTEM_SHUTDOWN "wamp.error.system_shutdown"
#define WAMP_ERROR_URI_NO_SUCH_PROCEDURE "wamp.error.no_such_procedure"
#define WAMP_ERROR_URI_NO_SUCH_REGISTRATION "wamp.error.no_such_registration"

// protocol extensions
#define WAMP_RUNTIME_ERROR "wamp.error.runtime_error"
#define WAMP_ERROR_BAD_PROTOCOL "wamp.error.bad_protocol"
#define WAMP_ERROR_UNEXPECTED_STATE "wamp.error.unexpected_state"

enum WampMsgType
{
    UNDEF=0,
    HELLO = 1,
    WELCOME = 2,
    ABORT = 3,
    CHALLENGE = 4,
    AUTHENTICATE = 5,
    GOODBYE = 6,
    HEARTBEAT = 7,
    ERROR = 8,
    PUBLISH = 16,
    PUBLISHED = 17,
    SUBSCRIBE = 32,
    SUBSCRIBED = 33,
    UNSUBSCRIBE = 34,
    UNSUBSCRIBED = 35,
    EVENT = 36,
    CALL = 48,
    CANCEL = 49,
    RESULT = 50,
    REGISTER = 64,
    REGISTERED = 65,
    UNREGISTER = 66,
    UNREGISTERED = 67,
    INVOCATION = 68,
    INTERRUPT = 69,
    YIELD = 70,

    WAMP_MSGID_MAX
};

typedef uint64_t t_request_id;
typedef uint64_t t_invoke_id;
typedef uint64_t t_sid;
typedef uint64_t t_subscription_id;

class wamp_session;
typedef std::weak_ptr<wamp_session> session_handle;

struct wamp_args
{
  json_array  args_list;
  json_object args_dict;
};

/* Represent the mode of a socket or wamp connection */
enum class connect_mode
{
  active,
  passive
};

/* Bit-flags for message serialisation types supported by WAMP */
enum class serialiser_type
{
  none = 0x00,
  json = 0x01,
  msgpack = 0x02
};

constexpr int all_serialisers =
  static_cast<int>(serialiser_type::json) |
  static_cast<int>(serialiser_type::msgpack);

/* Bit-flags for supported protocols */
enum class protocol_type
{
  none = 0x00,
  websocket = 0x01,
  rawsocket = 0x02
};

constexpr int all_protocols =
  static_cast<int>(protocol_type::websocket) |
  static_cast<int>(protocol_type::rawsocket);

} // namespace

#endif

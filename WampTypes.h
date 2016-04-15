#ifndef XXX_WAMPTYPES_H
#define XXX_WAMPTYPES_H

namespace XXX
{

#define WAMP_URI_NO_SUCH_PROCEDURE "wamp.error.no_such_procedure"
#define WAMP_URI_NO_SUCH_REGISTRATION "wamp.error.no_such_registration"
#define WAMP_ERROR_INVALID_URI "wamp.error.invalid_uri"
#define WAMP_RUNTIME_ERROR  "wamp.runtime_error"
#define WAMP_NO_SUCH_REALM  "wamp.error.no_such_realm"
// wamp.error.goodbye_and_out
// wamp.error.not_authorized

// wamp.error.no_such_subscription

//        wamp.error.invalid_argument

// wamp.error.procedure_already_exists

//        wamp.error.system_shutdown



//        wamp.error.close_realm
//        wamp.error.close_realm
//        wamp.error.not_authorized
//        wamp.error.authorization_failed
//        wamp.error.no_such_realm
//        wamp.error.no_such_role
//        wamp.error.canceled
//        wamp.error.option_not_allowed
//        wamp.error.no_eligible_callee
//        wamp.error.option_disallowed.disclose_me
//        wamp.error.network_failure


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

} // namespace

#endif


#ifndef XXX_CALLBACKS_H
#define XXX_CALLBACKS_H

#include <jalson/jalson.h>

#include <functional>
#include <string>
#include <memory>
#include <stdint.h>


// TODO: this might be come a client side for, for all types the client needs to use

namespace XXX {


class wamp_session;

struct wamp_args
{
  jalson::json_value  args_list;
  jalson::json_value  args_dict;
};

class router_conn;

typedef uint64_t t_request_id;
typedef uint64_t t_invoke_id;
typedef uint64_t t_sid;
typedef uint64_t t_subscription_id;

typedef std::weak_ptr<wamp_session> session_handle;
typedef std::function<void(wamp_session*)> session_closed_cb;


class wamp_error : public std::runtime_error
{
public:
  wamp_error(const char* error_uri, const char* what, wamp_args wa = wamp_args())
    : std::runtime_error(what),
      m_uri(error_uri),
      m_args(wa)
  {  }

  wamp_error(const char* error_uri, wamp_args wa = wamp_args())
    : std::runtime_error(error_uri),
      m_uri(error_uri),
      m_args(wa)
  {  }

  wamp_args& args() { return m_args; }
  const wamp_args& args() const { return m_args; }

  const std::string & error_uri() { return m_uri; }

private:
  std::string m_uri;
  wamp_args m_args;
};


struct invoke_details // TODO: rename
{
  std::string  uri;
  wamp_args args;
  jalson::json_object details;
  void * user;

  std::function<void(wamp_args)> yield_fn;
  std::function<void(wamp_args, std::string)> error_fn;

};



enum subscription_event_type
{
  e_sub_failed,
  e_sub_start,
  e_sub_update,
  e_sub_end
};

typedef std::function<void(subscription_event_type evtype,
                           const std::string& uri,
                           void* user) > subscription_status_cb;

typedef std::function<void(subscription_event_type evtype,
                           const std::string& uri,
                           const jalson::json_object& details,
                           const jalson::json_array& args_list,
                           const jalson::json_object& args_dict,
                           void* user) > subscription_cb;


typedef std::function<void(invoke_details&) > rpc_cb;

struct wamp_call_result
{
  t_request_id reqid;    /* protocol ID that was used */
  std::string procedure;
  bool was_error;
  std::string error_uri; // if was_error == true
  jalson::json_object details;
  wamp_args args;
  void * user;

  wamp_call_result()
    : reqid(0),
      was_error(false),
      user(0){}
};

typedef std::function< void (wamp_call_result) > wamp_call_result_cb;

typedef std::function<void(router_conn*,
                           int status, /* 0 is no error */
                           bool is_open)> router_session_connect_cb;

} // namespace XXX

#endif

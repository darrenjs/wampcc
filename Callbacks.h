#ifndef XXX_CALLBACKS_H
#define XXX_CALLBACKS_H


#include <jalson/jalson.h>

#include <functional>
#include <string>
#include <memory>
#include <stdint.h>


#include <iostream>  // TODO: remove, if SID is removed.


// TODO: this might be come a client side for, for all types the client needs to use

namespace XXX {


  class client_service;
  class dealer_service;
  class ev_inbound_message;


class session_error : public std::runtime_error
{
public:
  enum error_code
  {
    no_error = 0,
    msgbuf_full,
    bad_protocol,
    unknown,
    bad_json,
  };


  std::string uri;
  error_code err;

  session_error(const std::string& __uri,
                error_code __e = unknown)
  : std::runtime_error( __uri ),
    uri( __uri ),
    err( __e )
  {
  }

  session_error(const std::string& __uri,
                const std::string& __text,
                error_code __e = session_error::unknown)
  : std::runtime_error( __text ),
    uri( __uri ),
    err( __e )
  {
  }
};

struct wamp_args
{
  jalson::json_value  args_list;
  jalson::json_value  args_dict;
};

class router_conn;

typedef uint64_t t_connection_id;

typedef uint64_t t_request_id;
typedef uint64_t t_invoke_id;
typedef uint64_t t_client_request_id;
typedef uint64_t t_sid;
typedef uint64_t t_subscription_id;

typedef std::weak_ptr<t_sid> session_handle;


class invocation_exception : public std::runtime_error
{
public:

  invocation_exception(const char* error)
  : std::runtime_error(error)
  {  }

  invocation_exception(const char* error, wamp_args wa)
    : std::runtime_error(error),
      m_args(wa)
  {  }

  wamp_args& args() { return m_args; }
  const wamp_args& args() const { return m_args; }

private:
  wamp_args m_args;
};

struct invoke_details // TODO: rename
{
  t_request_id request_id;
  std::string  uri;
  wamp_args args;
  void * user;
  t_invoke_id id;

  std::function<void(t_request_id, wamp_args&)> reply_fn;

  invoke_details(t_invoke_id _id)
  : id(_id)
  {}
};

/* Information about a session that once set, will never change, and is used to
 * uniquely identify it. */
class SID
{
public:
   static SID null_sid;

  /* Creates the null session */
  SID() : m_unqiue_id(0) { }

  explicit SID(unsigned int s) : m_unqiue_id( s) { }

  bool operator==(SID rhs) const
  {
    return (this->m_unqiue_id == rhs.m_unqiue_id);
  }
  bool operator!=(SID rhs) const
  {
    return (this->m_unqiue_id != rhs.m_unqiue_id);
  }

  bool operator<(SID rhs) const
  {
    return this->m_unqiue_id < rhs.m_unqiue_id;
  }

  //std::string to_string() const;
  //static SID from_string(const std::string&);

  size_t unique_id() const { return m_unqiue_id; }

private:
  t_sid m_unqiue_id;

  friend std::ostream& operator<<(std::ostream&, const SID &);
};

std::ostream& operator<<(std::ostream& os, const SID & s);



class client_service;


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


typedef std::function<void(t_invoke_id,
                           invoke_details&,
                           const std::string&,
                           jalson::json_object&,
                           wamp_args&,
                           session_handle&,
                           void* user) > rpc_cb;

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

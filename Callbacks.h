#ifndef XXX_CALLBACKS_H
#define XXX_CALLBACKS_H


#include <jalson/jalson.h>

#include <functional>
#include <string>

#include <stdint.h>


// TODO: this might be come a client side for, for all types the client needs to use

namespace XXX {


typedef int t_request_id;
typedef uint64_t t_sid;

class client_service;

struct rpc_args
{
  jalson::json_value  args;
  jalson::json_object options;
};

struct call_info
{
  t_request_id reqid;     /* protocol ID that was used */
  std::string  procedure; /* rpc target */
};


typedef std::function<void(client_service&,
                           t_sid,
                           const std::string&,
                           int request_id,
                           rpc_args&,
                           void* user) > rpc_cb;


typedef std::function<  void (call_info&, rpc_args&, void*) > call_user_cb; // TODO: rename me


typedef std::function<void(uint64_t sid, int, void*)> tcp_connect_attempt_cb;

} // namespace XXX

#endif

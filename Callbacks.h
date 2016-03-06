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



typedef int t_request_id;
typedef uint64_t t_invoke_id;
typedef uint64_t t_client_request_id;
typedef uint64_t t_sid;

typedef std::weak_ptr<t_sid> session_handle;

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

struct rpc_args
{
  jalson::json_value  args;
  jalson::json_object options;
};

// TODO: no need to have this, can be expanded in places where it is
struct call_info
{
  t_request_id reqid;     /* protocol ID that was used */
  std::string  procedure; /* rpc target */  // TODO: standardise the varname for rpc name
};

typedef std::function<void(t_invoke_id,
                           const std::string&,
                           int request_id,
                           rpc_args&,
                           session_handle&,
                           void* user) > rpc_cb;

typedef std::function<  void (call_info&, rpc_args&, void*) > call_user_cb; // TODO: rename me

typedef std::function<void(session_handle, int, void*)> tcp_connect_attempt_cb;

} // namespace XXX

#endif

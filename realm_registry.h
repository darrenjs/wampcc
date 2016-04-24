#ifndef __REALM_REGISTRY_H_
#define __REALM_REGISTRY_H_


#include "Callbacks.h"

#include <jalson/jalson.h>

#include <map>
#include <mutex>
#include <atomic>

namespace XXX {

class Logger;

class realm_registry
{
public:

  typedef size_t t_realm_id;

  realm_registry(Logger*);
  ~realm_registry();

  t_realm_id realm_to_id(const std::string& realm, bool allow_create);

  const std::string& id_to_realm(t_realm_id id) const;

  const std::string& null_realm() const { return m_null_realm; }

private:
  Logger * __logptr;

  std::string m_null_realm;

  mutable std::mutex m_lock;
  std::atomic<t_realm_id> m_next_id;
  std::map< std::string, t_realm_id > m_realm_to_id;
  std::map< t_realm_id, std::string > m_id_to_realm;
};


} // namespace

#endif

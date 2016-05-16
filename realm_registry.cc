
#include "realm_registry.h"

#include "Logger.h"

#include <string.h>


namespace XXX
{

  realm_registry::realm_registry(Logger* /*logptr*/)
    : m_next_id(1)
  {
  }


  realm_registry::~realm_registry()
  {
  }


  realm_registry::t_realm_id realm_registry::realm_to_id(const std::string& realm,
                                                          bool allow_create)
  {
    std::unique_lock<std::mutex> guard( m_lock );

    auto iter = m_realm_to_id.find( realm );
    if (iter != m_realm_to_id.end())
      return iter->second;

    if (allow_create)
    {
      t_realm_id id = m_next_id++;
      m_realm_to_id[ realm ] = id;
      m_id_to_realm[ id ] = realm;
      return id;
    }
    else
      return 0;
  }


  const std::string& realm_registry::id_to_realm( realm_registry::t_realm_id id) const
  {
    std::unique_lock<std::mutex> guard( m_lock );
    auto iter = m_id_to_realm.find( id );
    if (iter != m_id_to_realm.end())
      return iter->second;
    else
      return m_null_realm;

  }

}

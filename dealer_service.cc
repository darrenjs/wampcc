#include "dealer_service.h"

#include "dealer_service_impl.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

dealer_service::dealer_service(kernel & __svc, dealer_listener* l)
  : m_impl(std::make_shared<dealer_service_impl>(__svc, l))
{
};


dealer_service::~dealer_service()
{
  m_impl->disown(); // prevent impl object making user callbacks
}


void dealer_service::listen(int port)
{
  m_impl->listen(port);
}


void dealer_service::register_procedure(const std::string& realm,
                                        const std::string& uri,
                                        const jalson::json_object& options,
                                        rpc_cb user_cb,
                                        void * user_data)
{
  m_impl->register_procedure(realm, uri, options, user_cb, user_data);
}


void dealer_service::publish(const std::string& topic,
                             const std::string& realm,
                             const jalson::json_object& options,
                             wamp_args args)
{
  /* USER thread */
  m_impl->publish(topic, realm, options, args);
}

} // namespace

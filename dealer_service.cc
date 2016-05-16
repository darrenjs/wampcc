#include "dealer_service.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "Callbacks.h"
#include "event.h"
#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"
#include "client_service.h"
#include "kernel.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

dealer_service::dealer_service(kernel & __svc, dealer_listener* l)
  :__logptr(__svc.get_logger()),
   m_kernel(__svc),
   m_sesman( new SessionMan(__svc) ),
   m_rpcman( new rpc_man(__svc, [this](const rpc_details&r){this->rpc_registered_cb(r); })),
   m_pubsub(new pubsub_man(__svc)),
   m_listener( l )
{
  m_kernel.get_event_loop()->set_session_man( m_sesman.get() );
  m_kernel.get_event_loop()->set_pubsub_man( m_pubsub.get() );
};


dealer_service::~dealer_service()
{
}


void dealer_service::rpc_registered_cb(const rpc_details& r)
{
  if (m_listener) m_listener->rpc_registered( r.uri );
}


void dealer_service::listen(int port)
{

  m_kernel.get_io()->add_server(
    port,
    [this](int /* port */,
           IOHandle* hndl)
    {
      // note, we dont make use of the user connection id for passive sessions
      auto sptr = m_sesman->create_session(hndl, true,  "" /* undefined realm */);

      auto handlers = server_msg_handler();

      handlers.inbound_call = [this](wamp_session* s, std::string u, wamp_args args, wamp_invocation_reply_fn f) {
        this->handle_inbound_call(s,u,std::move(args),f);
      };

      handlers.handle_inbound_publish  = [this](wamp_session* sptr, std::string uri, jalson::json_array & msg ) {
        m_pubsub->inbound_publish(sptr->realm(), uri, msg);
      };

      handlers.inbound_subscribe  = [this](wamp_session* sptr, jalson::json_array & msg) {
        m_pubsub->handle_inbound_subscribe(sptr, msg);
      };

      handlers.inbound_register  = [this](wamp_session* sptr, std::string uri) {
        return m_rpcman->handle_inbound_register(sptr, uri);
      };

      sptr->set_server_handler( std::move(handlers) );
    } );
}


void dealer_service::register_procedure(const std::string& realm,
                                        const std::string& uri,
                                        const jalson::json_object& options,
                                        rpc_cb user_cb,
                                        void * user_data)
{
  m_rpcman->register_internal_rpc_2(realm, uri, options, user_cb, user_data);
}


t_request_id dealer_service::publish(const std::string& topic,
                                     const std::string& realm,
                                     const jalson::json_object& options,
                                     wamp_args args)
{
  /* USER thread */
  return m_pubsub->publish(topic, realm, options, std::move(args));
}


void  dealer_service::handle_inbound_call(
  wamp_session* sptr, // TODO: possibly change this to a shared_ptr
  const std::string& uri,
  wamp_args args,
  wamp_invocation_reply_fn fn )
{
  /* EV thread */

  // TODO: use direct lookup here, instead of that call to public function, wheich can then be deprecated
  rpc_details rpc = m_rpcman->get_rpc_details(uri, sptr->realm());
  if (rpc.registration_id)
  {
    if (rpc.type == rpc_details::eInternal)
    {
      /* CALL request is for an internal procedure */

      if (rpc.user_cb)
      {
        invoke_details invoke;
        invoke.uri = uri;
        invoke.user = rpc.user_data;
        invoke.args = std::move(args);

        invoke.yield_fn = [fn](wamp_args args)
          {
            if (fn)
              fn(args, std::unique_ptr<std::string>());
          };

        invoke.error_fn = [fn](wamp_args args, std::string error_uri)
          {
            if (fn)
              fn(args, std::unique_ptr<std::string>(new std::string(error_uri)));
          };

        try
        {
          rpc.user_cb(invoke);
        }
        catch (XXX::invocation_exception& ex)
        {
          if (fn)
            fn(ex.args(), std::unique_ptr<std::string>(new std::string(ex.what())));
        }
        catch (std::exception& ex)
        {
          if (fn)
            fn(wamp_args(), std::unique_ptr<std::string>(new std::string(ex.what())));
        }
        catch (...)
        {
          if (fn)
            fn(wamp_args(), std::unique_ptr<std::string>(new std::string(WAMP_RUNTIME_ERROR)));
        }
      }

    }
    else
    {
      /* CALL request is for an external RPC */
      if (auto sp = rpc.sesionh.lock())
      {
        sp->invocation(rpc.registration_id,
                       jalson::json_object(),
                       args,
                       fn);
      }
    }
  }
  else
  {
    /* RPC uri lookup failed */
    _WARN_("call request failed, procuedure uri not found: " << sptr->realm() << "::" << rpc.uri);
    if (fn)
      fn(wamp_args(), std::unique_ptr<std::string>(new std::string(WAMP_ERROR_URI_NO_SUCH_PROCEDURE)));
  }

}

} // namespace

#include "dealer_service_impl.h"

#include "dealer_service.h"

#include "SessionMan.h"
#include "kernel.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "event_loop.h"
#include "IOLoop.h"
#include "IOHandle.h"
#include "Logger.h"


#include <iostream>

namespace XXX {

/* Constructor */
dealer_service_impl::dealer_service_impl(kernel & __svc, dealer_listener* l)
  :__logptr(__svc.get_logger()),
   m_kernel(__svc),
   m_sesman( new SessionMan(__svc) ),
   m_rpcman( new rpc_man(__svc, [this](const rpc_details&r){this->rpc_registered_cb(r); })),
   m_pubsub(new pubsub_man(__svc)),
   m_listener( l )
{
  // hb_func fn = [this]()
  //   {
  //     try{
  //       this->on_timer();
  //     } catch(...){}
  //     return true; // continue timer
  //   };
  // m_kernel.get_event_loop()->add_hb_target(std::move(fn));

}


dealer_service_impl::~dealer_service_impl()
{
  disown();
}


void dealer_service_impl::disown()
{
  std::unique_lock<std::recursive_mutex> guard(m_lock);
  m_listener = nullptr;
}


void dealer_service_impl::rpc_registered_cb(const rpc_details& r)
{
  std::unique_lock<std::recursive_mutex> guard(m_lock);
  if (m_listener) m_listener->rpc_registered( r.uri );
}



std::future<int> dealer_service_impl::listen(int port,
                                             auth_provider auth)
{
  std::promise<int> intPromise;
  std::future<int> fut = intPromise.get_future();

  m_kernel.get_io()->add_server(
    port,
    std::move(intPromise),
    [this, auth](int /* port */, std::unique_ptr<IOHandle> ioh)
    {
      /* IO thread */

      server_msg_handler handlers;

      handlers.inbound_call = [this](wamp_session* s, std::string u, wamp_args args, wamp_invocation_reply_fn f) {
        this->handle_inbound_call(s,u,std::move(args),f);
      };

      handlers.handle_inbound_publish  = [this](wamp_session* sptr, std::string uri, jalson::json_object options, wamp_args args)
        {
        // TODO: break this out into a separte method, and handle error
          m_pubsub->inbound_publish(sptr->realm(), uri, std::move(options), std::move(args));
        };

      handlers.inbound_subscribe  = [this](wamp_session* p, t_request_id request_id, std::string uri, jalson::json_object& options) {
        return this->m_pubsub->subscribe(p, request_id, uri, options);
      };

      handlers.inbound_register  = [this](std::weak_ptr<wamp_session> h,
                                          std::string realm,
                                          std::string uri) {
        return m_rpcman->handle_inbound_register(std::move(h), std::move(realm), std::move(uri));
      };

      {
        std::shared_ptr<wamp_session> sp =
          wamp_session::create( m_kernel,
                                std::move(ioh),
                                true, /* session is passive */
                                [this](session_handle s, bool b){ this->handle_session_state_change(s,b); },
                                handlers,
                                auth);
        m_sesman->add_session(sp);
        _INFO_( "session created #" << sp->unique_id() );
      }

    } );

  return fut;
}


void dealer_service_impl::publish(const std::string& topic,
                                  const std::string& realm,
                                  const jalson::json_object& options,
                                  wamp_args args)
{
  /* USER thread */

  std::weak_ptr<dealer_service_impl> wp = this->shared_from_this();

  // TODO: how to use bind here, to pass options in as a move operation?
  m_kernel.get_event_loop()->dispatch(
    [wp, topic, realm, args, options]()
    {
      if (auto sp = wp.lock())
      {
        sp->m_pubsub->inbound_publish(realm, topic, options, args);
      }
    }
  );

}


void dealer_service_impl::register_procedure(const std::string& realm,
                                             const std::string& uri,
                                             const jalson::json_object& options,
                                             rpc_cb user_cb,
                                             void * user_data)
{
  // TODO: dispatch this on the event thread?
  m_rpcman->register_internal_rpc_2(realm, uri, options, user_cb, user_data);
}


void dealer_service_impl::handle_inbound_call(
  wamp_session* sptr, // TODO: possibly change this to a shared_ptr
  const std::string& uri,
  wamp_args args,
  wamp_invocation_reply_fn fn )
{
  /* EV thread */

  // TODO: use direct lookup here, instead of that call to public function, wheich can then be deprecated
  try
  {
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

          rpc.user_cb(invoke);

        }
        else
          throw wamp_error(WAMP_ERROR_NO_ELIGIBLE_CALLEE);

      }
      else
      {
        /* CALL request is for an external RPC */
        if (auto sp = rpc.session.lock())
        {
          sp->invocation(rpc.registration_id,
                         jalson::json_object(),
                         args,
                         fn);
        }
        else
          throw wamp_error(WAMP_ERROR_NO_ELIGIBLE_CALLEE);
      }
    }
    else
    {
      /* RPC uri lookup failed */
      throw wamp_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
    }
  }
  catch (XXX::wamp_error& ex)
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


void dealer_service_impl::handle_session_state_change(session_handle sh, bool is_open)
{
  /* EV thread */
  if (!is_open)
  {
    m_pubsub->session_closed(sh);
    m_sesman->session_closed(sh);
  }
}


// bool dealer_service_impl::on_timer()
// {
//   /* EV thread */
//   m_sesman->handle_housekeeping_event();
//   return true;
// }

} // namespace XXX

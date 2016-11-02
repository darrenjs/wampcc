#include "XXX/dealer_service.h"

#include "XXX/kernel.h"
#include "XXX/rpc_man.h"
#include "XXX/pubsub_man.h"
#include "XXX/event_loop.h"
#include "XXX/io_loop.h"
#include "XXX/tcp_socket.h"
#include "XXX/log_macros.h"
#include "XXX/pre_session.h"
#include "XXX/tcp_socket.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

dealer_service::dealer_service(kernel* __svc, dealer_listener* l)
  : m_kernel(__svc),
    __logger(__svc->get_logger()),
   m_rpcman( new rpc_man(__svc, [this](const rpc_details&r){this->rpc_registered_cb(r); })),
   m_pubsub(new pubsub_man(__svc)),
   m_listener( l )

{
};


dealer_service::~dealer_service()
{
  std::map<t_sid, std::shared_ptr<wamp_session> > sessions;
  std::map<t_sid, std::shared_ptr<pre_session>  > pre_sessions;

  {
    std::lock_guard<std::mutex> guard(m_sesions_lock);
    m_sessions.swap( sessions );
    m_pre_sessions.swap( pre_sessions );
  }

  std::unique_lock<std::recursive_mutex> guard(m_lock);
  m_listener = nullptr;

  // trigger the destructors on sessions & pre_sessions, so that they are all
  // closed before dealer destruction can complete
  sessions.clear();
  pre_sessions.clear();
  m_server_sockets.clear();
}


std::future<int> dealer_service::listen(int port,
                                        auth_provider auth)
{

  auto on_new_client = [this, auth](int /* port */, std::unique_ptr<tcp_socket> ioh)
    {
      /* This lambda is invoked on the IO thread the when a socket has been
       * accepted. */

      auto protocol_ready_cb = [this, auth]( protocol_builder_fn builder,
                                             std::unique_ptr<tcp_socket> ioh)
        {
          /* Called on the IO thread, from the pre_session, when the
           * pre_session has identified the wire protocol to use. */

          server_msg_handler handlers;

          handlers.inbound_call = [this](wamp_session* s, std::string u, wamp_args args, wamp_invocation_reply_fn f) {
            this->handle_inbound_call(s,u,std::move(args),f);
          };

          handlers.handle_inbound_publish = [this](wamp_session* sptr, std::string uri, jalson::json_object options, wamp_args args)
          {
            // TODO: break this out into a separte method, and handle error
            m_pubsub->inbound_publish(sptr->realm(), uri, std::move(options), std::move(args));
          };

          handlers.inbound_subscribe = [this](wamp_session* p, t_request_id request_id, std::string uri, jalson::json_object& options) {
            return this->m_pubsub->subscribe(p, request_id, uri, options);
          };

          handlers.inbound_unsubscribe = [this](wamp_session* p, t_request_id request_id, t_subscription_id sub_id) {
            this->m_pubsub->unsubscribe(p, request_id, sub_id);
          };

          handlers.inbound_register = [this](std::weak_ptr<wamp_session> h,
                                             std::string realm,
                                             std::string uri) {
            return m_rpcman->handle_inbound_register(std::move(h), std::move(realm), std::move(uri));
          };

          int fd = ioh->fd();

          std::shared_ptr<wamp_session> sp =
          wamp_session::create( m_kernel,
                                std::move(ioh),
                                [this](std::weak_ptr<wamp_session> s, bool b){ this->handle_session_state_change(s,b); },
                                builder,
                                handlers,
                                auth);
          {
            std::lock_guard<std::mutex> guard(m_sesions_lock);
            m_sessions[ sp->unique_id() ] = sp;
          }

          LOG_INFO( "session created #" << sp->unique_id()
                    << ", protocol: " << sp->protocol_name()
                    << ", fd: " << fd);
        };

      auto on_closed = [this](std::weak_ptr<pre_session> sh)
        {
          /* EV thread */
          if (auto sp = sh.lock())
          {
            std::lock_guard<std::mutex> guard(m_sesions_lock);
            m_pre_sessions.erase( sp->unique_id() );
          }
        };

      auto sp = pre_session::create(m_kernel,
                                    std::move(ioh),
                                    on_closed,
                                    protocol_ready_cb);

      {
        std::lock_guard<std::mutex> guard(m_sesions_lock);
        m_pre_sessions[ sp->unique_id() ] = sp;
      }

    };


  /* Create the actual IO server socket */
  std::unique_ptr<tcp_socket> ts (new tcp_socket(m_kernel));
  tcp_socket * ptr = ts.get();
  m_server_sockets.push_back( std::move(ts) );

  auto fut = ptr->listen(
    port,
    [on_new_client, port ](tcp_socket*, std::unique_ptr<tcp_socket>& clt, int ec){
      /* IO thread */

      if (!ec)
      {
        on_new_client(port, std::move(clt));
      }
      else
      {
        std::cout << "TODO: handle case of failure to accept client, ec " << ec << std::endl;
      }
    });

  return fut;
}


void dealer_service::register_procedure(const std::string& realm,
                                        const std::string& uri,
                                        const jalson::json_object& options,
                                        rpc_cb user_cb,
                                        void * user_data)
{

  // TODO: dispatch this on the event thread?
  m_rpcman->register_internal_rpc_2(realm, uri, options, user_cb, user_data);

}


void dealer_service::publish(const std::string& topic,
                             const std::string& realm,
                             const jalson::json_object& options,
                             wamp_args args)
{
  /* USER thread */

  std::weak_ptr<dealer_service> wp = this->shared_from_this();

  // TODO: how to use bind here, to pass options in as a move operation?
  m_kernel->get_event_loop()->dispatch(
    [wp, topic, realm, args, options]()
    {
      if (auto sp = wp.lock())
      {
        sp->m_pubsub->inbound_publish(realm, topic, options, args);
      }
    }
  );

}


void dealer_service::rpc_registered_cb(const rpc_details& r)
{
  std::unique_lock<std::recursive_mutex> guard(m_lock);
  if (m_listener) m_listener->rpc_registered( r.uri );
}


void dealer_service::handle_inbound_call(
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
          wamp_invocation invoke;
          invoke.user = rpc.user_data;
          invoke.arg_list = std::move(args.args_list);
          invoke.arg_dict = std::move(args.args_dict);

          invoke.yield = [fn](jalson::json_array arg_list, jalson::json_object arg_dict)
            {
              wamp_args args { std::move(arg_list), std::move(arg_dict) };
              if (fn)
                fn(args, std::unique_ptr<std::string>());
            };

          invoke.error = [fn](std::string error_uri, jalson::json_array arg_list, jalson::json_object arg_dict)
            {
              wamp_args args { std::move(arg_list), std::move(arg_dict) };
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


void dealer_service::handle_session_state_change(std::weak_ptr<wamp_session> wp, bool is_open)
{
  /* EV thread */
  if (auto session = wp.lock())
  {
    if (!is_open)
    {
      m_rpcman->session_closed(session);
      m_pubsub->session_closed(session);

      std::lock_guard<std::mutex> guard(m_sesions_lock);
      m_sessions.erase( session->unique_id() );
    }
  }
}


std::future<void> dealer_service::close()
{
  // ANY thread

  {
    std::lock_guard<std::mutex> guard(m_sesions_lock);
    for (auto & item : m_sessions)
    {
      item.second->close();
    }
  }

  // TODO: next, need to remove all listen sockets we have

  return m_promise_on_close.get_future();
}

void dealer_service::check_has_closed()
{
  // TODO: perform state check to see if all resources this class is responsible
  // for have closed, in which case we can set the close promise

  size_t num_sessions;
  {
    std::lock_guard<std::mutex> guard(m_sesions_lock);
    num_sessions = m_sessions.size();
  }

  if (num_sessions == 0)
  {
    m_promise_on_close.set_value();
  }
}

} // namespace


#include "XXX/kernel.h"
#include "XXX/wamp_session.h"
#include "XXX/io_connector.h"
#include "XXX/io_loop.h"
#include "XXX/io_handle.h"
#include "XXX/rawsocket_protocol.h"
#include "XXX/websocket_protocol.h"


#include <memory>
#include <iostream>
#include <unistd.h>

//using namespace std;

void procedure_cb(XXX::wamp_invocation& invocation)
{
  // TODO: show example of using callback data
//   const callback_t* cbdata = (callback_t*) invocation.user;

  std::cout << "rpc invoked" << std::endl;


  XXX::wamp_args reply;
  reply.args_list = jalson::json_array({"hello", "world"});


//   LOG_INFO ("CALLEE has procuedure '"<< invocation.uri << "' invoked, args: " << invocation.args.args_list
//           << ", user:" << cbdata->request );

// //  throw std::runtime_error("bad alloc");
//   auto my_args = invocation.args;

//   my_args.args_list = jalson::json_array();
//   jalson::json_array & arr = my_args.args_list.as_array();
//   arr.push_back("hello");
//   arr.push_back("back");

  invocation.yield(reply);
}

struct connect_options
{
  bool resolve_hostname;
  int  timeout_millisec;

  enum t_protocol
  {
    e_rawsocket,
    e_websocket
  } protocol;

  enum t_encoding
  {
    e_json,
    e_msgpack
  } encoding;


  connect_options(t_protocol p, t_encoding e, bool resolve=true, int timeout=1000)
    : resolve_hostname(resolve),
      timeout_millisec(timeout),
      protocol(p),
      encoding(e)
  {
  }
};


struct io_handle_guard
{
  std::unique_ptr<XXX::io_handle> handle;

  io_handle_guard(std::unique_ptr<XXX::io_handle> h)
    : handle(std::move(h))
  {
  }

  ~io_handle_guard()
  {
    if (handle)
    {
      std::cout << "we have to close the io\n";
      auto fut = handle->request_close();
      fut.wait();
    }
  }

};


/** Convenience function

 * currently is sychronous.
*/
std::shared_ptr<XXX::wamp_session> connect_to_server(
  XXX::kernel* kernel,
  const std::string& host,
  const std::string& port,
  const XXX::client_credentials& credentials,
  connect_options options,
  std::function<void( std::shared_ptr<XXX::wamp_session> )> on_close)
{
  /* Create a socket connector.  This will immediately make an attempt to
   * connect to the target end point.  The connector object is a source of async
   * events (the connect and disconnect call back), and so must be managed
   * asynchronously. */
  std::shared_ptr<XXX::io_connector> conn
    = kernel->get_io()->add_connection(host, port, options.resolve_hostname);

  auto connect_fut = conn->get_future();

  /* Wait until the connector has got a result. The result can be successful,
   * in which case a socket is available, or result could be a failure, in
   * which case either an exception will be available or a null pointer. */
  std::future_status status;
  do
  {
    // TODO: should use wait_until?
    status = connect_fut.wait_for(std::chrono::milliseconds(options.timeout_millisec));

    if (status == std::future_status::timeout)
    {
      std::cout << "got timeout\n";
      conn->async_cancel();
      throw std::runtime_error("connect timeout");
    }
  } while (status != std::future_status::ready);

  /* The future has a result; our socket connection could be available. */
  // auto ioh = connect_fut.get();
  // std::cout << "going to throw\n";
  // throw std::runtime_error("decided to throw");

  io_handle_guard io_guard ( connect_fut.get() );

  if (!io_guard.handle)
    throw std::runtime_error("connect failed");

  std::mutex               session_mutex;
  std::condition_variable  session_condition;

  auto fn = [&](XXX::session_handle wp, bool is_open)
    {
      if (auto sp = wp.lock())
      {
        if (is_open)
        {
          session_condition.notify_all();
        }
      }
    };

  // TODO: should try to ensure WS can only be created using an io_handle this
  // is open ... could throw an exception.

  std::cout << "attempt create\n";
  XXX::rawsocket_protocol::options rs_options;
  std::shared_ptr<XXX::wamp_session> ws (
    XXX::wamp_session::create<XXX::rawsocket_protocol>(*kernel,
                                                       std::move(io_guard.handle),
                                                       fn, rs_options)
    );

  std::cout << "got wamp_session, attempt hello\n";
  ws->initiate_hello(credentials);

  // std::cout << "going to throw\n";
  // throw std::runtime_error("decided to throw");

  /* Wait for the WAMP session to authenticate and become open */
  std::unique_lock<std::mutex> guard(session_mutex);
  std::cout << "waiting for session to open...\n";
  bool hasevent = session_condition.wait_for(guard,
                                             std::chrono::milliseconds(options.timeout_millisec),
                                             [&](){ return ws->is_open(); });

  if (!hasevent)
    throw std::runtime_error("failed to establish WAMP session after timeout");

  return ws;
}

/*

  need a simple connect interface

  need to support async and sync, so provide basic atomics to support both user approaches

  WS closure, and IO closure are huge problems (active objects)

  how to register an RPC mulitpe times?

  if I want to sync, then how do I also deal with WS disconnects, which can
  happen at any time?

  is there any way I can support WS delete?

 */
int main(int /* argc */, char** /* argv */)
{
  auto logger = XXX::logger::stdlog(std::cout,
                                    XXX::logger::levels_upto(XXX::logger::eInfo), 1);

  std::unique_ptr<XXX::kernel> kernel( new XXX::kernel({},logger));
  kernel->start();

  XXX::client_credentials credentials;
  credentials.realm="default_realm";
  credentials.authid="peter";
  credentials.authmethods = {"wampcra"};
  credentials.secret_fn = []() -> std::string { return "secret2XXX"; };

  connect_options options(connect_options::e_rawsocket, connect_options::e_json);
  std::shared_ptr<XXX::wamp_session> ws;

  while (!ws)
  {
    try
    {
      ws = connect_to_server(kernel.get(), "localhost", "55555", credentials, options, nullptr);
    }
    catch (const std::exception & e)
    {
      std::cout << "failed to get wamp session: " << e.what() << std::endl;
      sleep(1);
      continue;
    }
    catch (...)
    {
      std::cout << "failed to get wamp session: unknown exception" <<  std::endl;
      sleep(1);
      continue;
    }


    ws->provide("hello",
                jalson::json_object(),
                procedure_cb,
                nullptr);

    while (ws->is_open())
    {
      sleep(1);
    }
  }

  auto fut_closed = ws->close();
  fut_closed.wait();

  kernel.reset();

  return 0;
}

/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <iostream>
#include <memory>
#include <set>
#include <ctime>
#include <iomanip>
#include <sstream>

/*
An example of a wamp-enabled application server.

This class provides a wamp listener that allows connection from wamp clients and
directly handles client service requests (i.e. register, call, publish &
subscribe).

Typically wamp clients connect to a wamp server that acts as a router/dealer.
Client service requests are then resolved via the router/dealer interacting with
other wamp clients that provide the target services (e.g., clients that
implement procedures or publish data).

With a wamp-enabled application server, the server application itself implements
the services requested by the client.  In programmatic terms this simply means
that on arrival of a client request a callback is triggered that is implemented
by the application, typically resulting in a wamp response or wamp error.

The following example shows the implementation of the wamp CALL request.
*/
class server_application
{
public:
  server_application()
    : m_kernel(new wampcc::kernel(wampcc::config()
                                  /*, wampcc::logger::console()*/)),
      m_server_sock(m_kernel.get()),
      m_is_closing(false)
  {
  }

  void start_listen(const std::string& listen_host,
                    const std::string& listen_port);

  std::future<void> can_terminate() { return m_can_terminate.get_future(); }

private:
  void on_new_client(std::unique_ptr<wampcc::tcp_socket>& client_sock,
                     wampcc::uverr ec);

  void on_session_state_changed(wampcc::wamp_session& ws, bool is_open);

  void on_call(wampcc::wamp_session&,
               wampcc::t_request_id,
               std::string&,
               wampcc::json_object&,
               wampcc::wamp_args&);

  std::unique_ptr<wampcc::kernel> m_kernel;
  wampcc::tcp_socket m_server_sock;

  /* Collection of live sessions. Session lifetime is determined by its
   * existence in this container. */
  std::set<std::shared_ptr<wampcc::wamp_session>> m_sessions;

  /* Is the server application shutting down? */
  bool m_is_closing;

  /* Set once the server application has closed all sessions and IO, and is
   * ready to terminate. */
  std::promise<void> m_can_terminate;
};


void server_application::start_listen(const std::string& listen_host,
                                      const std::string& listen_port)
{
  using namespace std::placeholders;

  /* Start socket listen and accept */

  auto fut = m_server_sock.listen(
    listen_host, listen_port,
    std::bind(&server_application::on_new_client, this, _1, _2),
    wampcc::tcp_socket::addr_family::inet4);

  /* Check the socket listen was successful */

  if (fut.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
    throw std::runtime_error("timeout during listen on port " + listen_port);

  if (auto ec = fut.get())
    throw std::runtime_error("listen failed on port " + listen_port +
                             ": err " + std::to_string(ec.os_value()) + ", " +
                             ec.message());
}


void server_application::on_new_client(
  std::unique_ptr<wampcc::tcp_socket>& client_sock,
  wampcc::uverr ec)
{
  /* Invoked on the wampcc IO thread when a new client socket has connected.
   * The task now is to create a new wamp_session from that client socket. */

  using namespace std::placeholders;

  if (m_is_closing)
    return;

  if (ec) {
    std::cout << "error for socket accept() : " << ec.os_value() << ", "
              << ec.message() << std::endl;
    return;
  }

  std::cout
    << "client connected, local address "
    << client_sock->get_local_address().to_string() << ":"
    << client_sock->get_local_port() << ", peer address "
    << client_sock->get_peer_address().to_string() << ":"
    << client_sock->get_peer_port()
    << std::endl;;

  wampcc::kernel * kernel = client_sock->get_kernel();

  /* Authentication policy -- for this example we don't require any
   * authentication. */
  auto auth = wampcc::auth_provider::no_auth_required();

  /* Set up the handlers which get invoked in response to events on the wamp
   * session. In this example we only implement the WAMP CALL interface; the
   * others are left defaulted (which send rejects if triggered). */
  wampcc::server_msg_handler handlers;
  handlers.on_call = std::bind(&server_application::on_call, this, _1, _2, _3, _4, _5);

  /* Create a lambda that is able to build a protocol object. In here we control
   * what kind of protocol the wamp session will use;q here it is
   * selector_protocol, which later selects between qwebsocket and rawsocket. */
  auto builder_fn = [](wampcc::tcp_socket* sock,
                       wampcc::protocol::t_msg_cb msg_cb,
                       wampcc::protocol::protocol_callbacks cb) {
    wampcc::selector_protocol::options opts;
    opts.protocols = wampcc::all_protocols;
    opts.serialisers = wampcc::all_serialisers;
    std::unique_ptr<wampcc::protocol> protocol(
      new wampcc::selector_protocol(sock->get_kernel(), sock, msg_cb, cb, opts));
    return protocol;
  };

  /* Create a wamp_session based on the connected socket.  Ownership of the
   * socket is transferred from the caller of this method into the
   * wamp_session. */
  try {
    std::shared_ptr<wampcc::wamp_session> ws = wampcc::wamp_session::create(
      kernel, std::move(client_sock),
      std::bind(&server_application::on_session_state_changed, this, _1, _2),
      builder_fn,
      handlers,
      auth);

    /* Store the session.  The session lifetime is tied to the object's
     * lifetime, so by added to this collection we keep the wamp_session object
     * in existence. */
    m_sessions.insert(std::move(ws));
  }
  catch (const std::exception& e) {
    std::cout << "exception during wamp_session create: " << e.what() << std::endl;
  }
}


void server_application::on_call(wampcc::wamp_session& session,
                                 wampcc::t_request_id request_id,
                                 std::string& procedure,
                                 wampcc::json_object&,
                                 wampcc::wamp_args&)
{
  /* Invoked on the wampcc event thread when a WAMP CALL message has arrived
   * from the peer.  The task in here is to identify the procedure being
   * requested and invoke the corresponding action (typically returning a WAMP
   * RESULT), or, if the procedure is unsupported, reply with a WAMP ERROR. */

  std::cout << "session #" << session.unique_id() <<" calling '"
            << procedure << "'" << std::endl;

  if (procedure=="time") {
    std::time_t t = std::time(nullptr);
    std::ostringstream utc, loc;

#if defined __GNUC__ && __GNUC__ < 5
    // gcc 4.8 doesn't support std::put_time
    struct tm tmutc;
    struct tm tmloc;
    gmtime_r(&t, &tmutc);
    localtime_r(&t, &tmloc);
    char buf[64];
    asctime_r(&tmutc, buf);
    buf[strlen(buf)-1] = '\0'; // remove newline
    utc << buf;
    asctime_r(&tmloc, buf);
    buf[strlen(buf)-1] = '\0'; // remove newline
    loc << buf; 
#else
    utc << std::put_time(std::gmtime(&t), "%c %Z");
    loc << std::put_time(std::localtime(&t), "%c %Z");
#endif

    wampcc::json_object reply;
    reply.insert({"UTC", utc.str()});
    reply.insert({"localtime", loc.str()});

    session.result(request_id, {}, reply);
  }
  else if (procedure=="close") {

    std::cout << "server terminating..." << std::endl;
    m_is_closing = true;

    /* Request asynchronous close of all current sessions */
    for (auto& session : m_sessions)
      session->close();

    /* Synchronously close the server socket, which is safe here because it is
     * being invoked from the wampcc event thread, rather that the wamp IO
     * thread. */
    m_server_sock.close().wait();
  }
  else
    session.call_error(request_id, WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
}


void server_application::on_session_state_changed(wampcc::wamp_session& ws, bool is_open)
{
  /* Invoked on the wampcc event thread when wamp_session has transitioned to
   * either the open state or the closed state. */

  if (is_open) {
    std::cout << "session #" << ws.unique_id() << " open" << std::endl;
  }
  else {
    std::cout << "session #" << ws.unique_id() << " closed" << std::endl;

    /* Once a session has closed it is safe to delete */
    m_sessions.erase( ws.shared_from_this() );

    if (m_is_closing && m_sessions.empty())
      m_can_terminate.set_value();
  }
}


int main(int argc, char** argv)
{
  try {
    if (argc<2)
      throw std::runtime_error("please provide port");

    std::string port = argv[1];
    server_application server_app;

    server_app.start_listen("localhost", port);

    /* Suspend main thread until server application is ready to terminate */
    server_app.can_terminate().wait();

  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}

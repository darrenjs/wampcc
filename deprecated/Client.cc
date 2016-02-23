#include "Client.h"
#include "IOHandle.h"
#include "Common.h"
#include "Session.h"
#include "IOLoop.h"
#include "event_loop.h"

#include <iostream>
#include <thread>
#include <memory>


#include <uv.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

namespace XXX {

struct Client::Connection
{
  uv_tcp_t uv_tcp_handle;
  Session * session;
  Client * owner;
  Client::Request request;
};





/* Constructor */
Client::Client()
  :
    m_session(0)
{
}

/* Destructor */
Client::~Client()
{
}



  static event_loop temp_evl( nullptr );

/* Called on the IO thread when a connection attempt has completed */
static void __on_connect(uv_connect_t* __req, int status )
{
  std::unique_ptr<uv_connect_t> connect_req(__req); // auto deleter

  Client::Connection * connection = (Client::Connection *) connect_req->data;

  if (status < 0)
  {
    fprintf(stderr, "connect error %s\n", uv_strerror(status));
    if (connection->request.cb)
      connection->request.cb( 0, status);
  }
  else
  {
    // IOLoop has set itself as the uv_loop data member
    IOLoop * myIOLoop = static_cast<IOLoop* >(__req->handle->loop->data);

    IOHandle* iohandle  = new IOHandle(  (uv_stream_t *) &connection->uv_tcp_handle,
                                         myIOLoop,
                                         0);

    connection->session = new Session(SID(), nullptr, iohandle, nullptr, temp_evl, false);

    if (connection->request.cb)
      connection->request.cb( connection->session, 0);
  }


}



void Client::start()
{
  m_loop = new IOLoop();

  m_loop->m_async_cb.push_back(
    [this](int){this->handle_async();});

  // start the IOLoop thread; returns immediately
  m_loop->start();
}


void Client::connect(const Request& req)
{

  {
    std::lock_guard<std::mutex> guard( m_requests_lock );
    m_requests.push_back( req );
  }
  m_loop->async_send();

}



/* Called on the IO thread, and is the only place we can interact with IO
 * related data structures. */
void Client::handle_async()
{
  std::cout << __FUNCTION__ << "\n";
  decltype( m_requests ) tmp;
  {
    std::lock_guard<std::mutex> guard( m_requests_lock );
    tmp.swap(m_requests);
  }

  for (auto & req : tmp)
  {
    std::unique_ptr<Connection> handle ( new Connection() );
    uv_tcp_init(m_loop->uv_loop(), &handle->uv_tcp_handle);
    handle->request = req;
    handle->owner = this;

    uv_tcp_t tcp_handle;
    uv_tcp_init(m_loop->uv_loop(), &tcp_handle);

    uv_connect_t * connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    connect_req->data = handle.get();

    struct sockaddr_in dest;
    uv_ip4_addr(req.addr.c_str(), req.port, &dest);

    int r = uv_tcp_connect(connect_req,
                           &handle->uv_tcp_handle,
                           (const struct sockaddr*)&dest,
                           __on_connect);

    if (!r)
    {
      // TODO : return this error on the IO thread, eg we get an immediate error
      // if we try to connect to 227.43.0.1 although, I think it is better to
      // return it immediately.
      std::cout << "r=" << r << "\n";
    }

    {
      std::lock_guard<std::mutex> guard( m_handles_lock );
      m_handles.push_back(handle.get());
      handle.release();
    }
  }
}


} // namespace XXX

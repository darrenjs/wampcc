#include "NexioServer.h"

#include "SessionMan.h"
#include "IOHandle.h"
#include "Session.h"
#include "TopicMan.h"
#include "rpc_man.h"
#include "client_service.h"

#include <uv.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>

#include <assert.h>
#include <string.h>

namespace XXX {

size_t counter = 0;

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;





/*

Warning: If your program is meant to be used with other programs it may
knowingly or unknowingly be writing to a pipe. This makes it susceptible to
;;aborting on receiving a SIGPIPE. It is a good idea to insert:

  signal(SIGPIPE, SIG_IGN)

in the initialization stages of your application.

 */

/*
All handles and requests have a void* data member which you can set to the
context and cast back in the callback.
*/


/*

send to all

  - get list of streams

  - write bytes to stream

*/

NexioServer::NexioServer(Config c)
  : m_config(c),
    m_evl( nullptr ),
//    m_thread(&NexioServer::util_thread_tep, this),
    m_sesman(new SessionMan(nullptr,  m_evl)),
    m_topicman(new TopicMan(nullptr)),
    m_io_loop( nullptr, nullptr, nullptr ),
    m_rpcman( new rpc_man(nullptr, m_evl, [](const rpc_details*){}))
{
  // TODO: I think this is the old style... probably not used?

  // m_rpcman->rcp_register( "echo",
  //                         [=] (int i,
  //                              const jalson::json_array*,
  //                              const jalson::json_object*, void*)
  //                         { call_me(i); },
  //                         nullptr );

}


//  #c++11 tip = define destruction in impl file, so that UP<> will find class
//  #definition it needs
NexioServer::~NexioServer()
{
  delete m_rpcman;
}


static void io_on_timer(uv_timer_t* handle)
{
  NexioServer* p = (NexioServer*) handle->data;
  try
  {
    p->on_timer();
  }
  catch(...)
  {
    // TODO: add logging
  }
}

void io_on_close(uv_handle_t* handle)
{
  std::cout << "io_on_close \n";

  IOHandle * iohandle = (IOHandle *) handle->data;
  iohandle->on_close();
}


static void after_write(uv_write_t*, int)
{
  // write_req_t* wr = (write_req_t*)req;

  // if (wr->buf.base != NULL)
  //   free(wr->buf.base);
  // free(wr);

  // if (status == 0)
  //   return;

  // fprintf(stderr, "uv_write error: %s\n", uv_strerror(status));

  // if (status == UV_ECANCELED)
  //   return;

  // assert(status == UV_EPIPE);
  // uv_close((uv_handle_t*)req->handle, io_on_close);
}



// wrapper to read
void write_data(uv_stream_t *stream_hdl,
                size_t size,
                uv_buf_t buf,
                uv_write_cb cb)
{
  cb = after_write;

  // create a new write request, and initialise a buffer to use
  write_req_t *req = (write_req_t *) malloc(sizeof(write_req_t));

  req->buf = uv_buf_init((char *) malloc(size), size);
  memcpy(req->buf.base, buf.base, size);

  // write bytes to a stream.  'req' is the request object which gets passed to
  // the callback
  uv_write((uv_write_t *)  req,
           (uv_stream_t *) stream_hdl,
           &req->buf,
           1,
           cb);
}

  // construct loop
uv_loop_t *loop = 0;


/* Main reader callback */
void io_on_read(uv_stream_t*  uvh,
             ssize_t nread ,
             const uv_buf_t* buf)
{
//  std:: cout << "UV_EOF=" << UV_EOF << "\n"; 4095

  std::cout << "onread: " << uvh << " nread " << nread
            << ", len " << buf->len << "\n";
  if (nread < 0)
  {
    if (nread == UV_EOF)
    {
      std::cout << "stream EOF\n";
    }
    uv_close((uv_handle_t*)uvh, io_on_close);
  }
  else if (nread > 0)
  {
    IOHandle * iohandle = (IOHandle *) uvh->data;
    iohandle->on_read(buf->base, nread);
  }
  // NOTE: is nread is 0, it suggests a EAGAIN type operation.
}

void alloc_buffer(uv_handle_t* /* handle */,
                  size_t suggested_size,
                  uv_buf_t* buf )
{
  *buf = uv_buf_init((char *) malloc(suggested_size), suggested_size);
}


void tcp_connection_cb(uv_stream_t* server, int status)
{
  // IOLoop has set itself as the uv_loop data member
//  IOLoop * myIOLoop = static_cast<IOLoop* >(server->loop->data);

  std::cout << "received connection\n";

  if (status < 0)
  {
    fprintf(stderr, "New connection error %s\n", uv_strerror(status));
    return;
  }

  uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, client);

  if (uv_accept(server, (uv_stream_t *) client) == 0)
  {
    // TODO: in here, I need to get access to the IOLoop
//    IOHandle* iohandle = new IOHandle(  (uv_stream_t *) client, myIOLoop, 0 );

    int fd = client->io_watcher.fd;
    std::cout << "accept: type=" << client->type
              << ", fd=" << fd << "\n";

    if (client->type == UV_TCP)
    {
      std::cout << "got tcp fd "<<  fd<< "\n";
    }

    // register the stream before beginning read operations
//    NexioServer* instance = (NexioServer*)server->data;

//    instance->new_client(iohandle);

    // NOTE: registration of read event moved into the handle

    // // new client is accepted, identified via its stream handle ... need to put
    // // in place a lot more session tracking here.
    // uv_read_start((uv_stream_t *) client, alloc_buffer, io_on_read);
  }
  else
  {
    uv_close((uv_handle_t *) client, NULL);
  }



}

// void NexioServer::util_thread_tep()
// {
//   int i = 0;
//   while(1)
//   {
//     i++;
//     sleep(7);
//     //std::cout << "util thread\n";
//     m_sesman->heartbeat_all();
//     if (i%5 == 0)
//       m_sesman->close_all();

//   }


// }

void io_on_idle(uv_idle_t* /*handle*/) {
  counter++;

  std::cout << "idle " << counter << "\n";
  // if (counter >= 10e6)
  // {
  //   std::cout << "done\n";

  //   // stop the handle, which removes it from the EVL
  //   uv_idle_stop(handle);
  // }
}

void NexioServer::init()
{
}

void NexioServer::new_start()
{

}

void NexioServer::start()
{

  // construct loop
  // loop = (uv_loop_t *)malloc(sizeof(uv_loop_t));
  // uv_loop_init(loop);

  loop = m_io_loop.uv_loop();


  // NOTE:  not using idler anymore, because it causes 100% CPU
  // uv_idle_t idler;
  // uv_idle_init(loop, &idler);
  // uv_idle_start(&idler, io_on_idle);

  uv_timer_t timer_req;
  uv_timer_init(loop, &timer_req);
  timer_req.data = this;
  uv_timer_start(&timer_req, io_on_timer, 60000, 60000);



  // Create a tcp socket, and configure for listen
  uv_tcp_t server;
  uv_tcp_init(loop, &server);
  server.data = this;

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", 55555, &addr);

  unsigned flags = 0;
  uv_tcp_bind(&server, (const struct sockaddr*)&addr, flags);
  int r = uv_listen((uv_stream_t *) &server, 5, tcp_connection_cb);
  std::cout << "loop starting, r="<< r << "\n";

  m_io_loop.run_loop();

  // // invoke event loop
  // uv_run(loop, UV_RUN_DEFAULT);

  // uv_loop_close(loop);
  // std::cout << "loop ending\n";
  // free(loop);
}


void NexioServer::addTopic(Topic* topic)
{
  m_topicman->add_topic( topic );
}

void NexioServer::on_timer()
{
//  m_sesman->on_timer();
}

void NexioServer::call_me(int)
{
  // int requestid;
  // void args;
  // int sessionid;




  // TODO: sooo.... how do I send a reply back from here?


  // TODO: I might want to send a reply

  // TODO: I might throw an exception

  // TODO: I might simply return a value




}





} // namespace XXX

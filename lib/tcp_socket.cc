#include <XXX/tcp_socket.h>
#include <XXX/kernel.h>
#include <XXX/io_loop.h>

#include <iostream>

namespace XXX {

tcp_socket::tcp_socket(kernel* k)
  : m_kernel(k),
    m_uv_tcp( new uv_tcp_t() ),
    m_state(e_created),
    m_io_closed_future(m_io_closed_promise.get_future())
{
  uv_tcp_init(m_kernel->get_io()->uv_loop(), m_uv_tcp);
  m_uv_tcp->data = new uv_handle_data(uv_handle_data::e_tcp_socket, this);
}


tcp_socket::~tcp_socket()
{
//  std::cout  << this << " "<< "~tcp_socket -->" << std::endl;

  {
    std::unique_lock<std::mutex> guard(m_state_lock);
    if ((m_state != e_closing) && (m_state != e_closed))
    {
      m_state = e_closing;
      std::cout  << this << " "<< "~server_handle close_server_handle" << std::endl;
      m_kernel->get_io()->close_tcp_socket(m_uv_tcp);
    }
  }

  m_io_closed_future.wait();
  delete m_uv_tcp;
//  std::cout  << this << " "<< "~tcp_socket <--" << std::endl;
}


bool tcp_socket::is_open() const
{
  std::unique_lock<std::mutex> guard(m_state_lock);
  return m_state == e_connected;
}


async_value tcp_socket::connect(std::string addr, int port)
{
  bool resolve_hostname = false;

  std::shared_ptr<std::promise<void>> completion_promise( new std::promise<void>() );

  auto success_fn = [completion_promise,this]() {

    {
      std::unique_lock<std::mutex> guard(m_state_lock);
      m_state = e_connected;
    }
    std::cout << "setting promise for success\n";
    completion_promise->set_value();

  };
  auto failure_fn = [completion_promise,this](std::exception_ptr e) {
    std::cout << "setting promise for failure\n";
    completion_promise->set_value();
  };

  // std::unique_lock<std::mutex> guard(sp->m_mutex);
  m_kernel->get_io()->connect2(m_uv_tcp,
                               addr,
                               std::to_string(port),
                               resolve_hostname,
                               success_fn,
                               failure_fn);


  return async_value( completion_promise );
}


void tcp_socket::do_close()
{
  /* IO thread */

  //std::cout << this << " " << "IO tcp_socket::do_close -->" << std::endl;


  // TODO: not sure when I should lock in here.  Need to think of the race
  // conditions again.  I cant remember what the race condition was.

  //std::cout  << this << " "<< "IO tcp_socket::do_close uv_close" << std::endl;
  uv_close((uv_handle_t*) m_uv_tcp, [](uv_handle_t * h) {
      uv_handle_data * ptr = (uv_handle_data*) h->data;
      {
        std::lock_guard< std::mutex > guard (ptr->tcp_socket_ptr()->m_state_lock);
        ptr->tcp_socket_ptr()->m_state = e_closed;
      }
      ptr->tcp_socket_ptr()->m_io_closed_promise.set_value();
//      delete h;
    });
  // m_uv_tcp = 0;
  // m_state = e_closed;
  // std::cout  << this << " "<< "IO tcp_socket::do_close set_value" << std::endl;
  // m_io_closed_promise.set_value();
  // std::cout  << this << " "<< "IO tcp_socket::do_close <--" << std::endl;
}


int tcp_socket::fd() const
{
  return m_uv_tcp->io_watcher.fd;
}


void tcp_socket::start_read()
{
  // call on uv:  start_read

/*
  how do I have this callback?

  i.e. i dont want all the code in the io_loop

  and, i need to put in a callback pointer



*/
}


} // namespace XXX

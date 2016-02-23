#ifndef XXX_CLIENT_H
#define XXX_CLIENT_H


#include <string>
#include <vector>
#include <mutex>
#include <list>


namespace XXX {

  class event_loop;
  class IOHandle;
  class Session;
  struct IOLoop;

  typedef void (*connect_cb)(class XXX::Session* session, int status);

  class Client
  {
  public:

    struct Request
    {
      std::string addr;
      int         port;
      connect_cb  cb;
      void *      data;

      Request() : port(0), data(nullptr) {}
    };

    Client();
    ~Client();

    // start the event loop
    void start();
    void init();

    /* Make an asynchronous connection attempt to the specified end point */
    void connect(const Request&);

    void on_timer() {}

  public:
    struct Connection;


  private:
    Client(const Client&); // no copy
    Client& operator=(const Client&); // no assignment


    Session * m_session;
    IOLoop * m_loop;

    void handle_async();

    std::vector<Request>      m_requests;
    std::mutex                m_requests_lock;

    std::list< Connection* > m_handles;
    std::mutex               m_handles_lock;
  };

} // namespace XXX

#endif

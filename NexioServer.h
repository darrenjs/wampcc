
#include  "IOLoop.h"
#include  "event_loop.h"

#include <Logger.h>

#include <memory>
#include <thread>
#include <unistd.h>

namespace XXX {

class Impl;
  class   client_service;
class SessionMan;
class TopicMan;
class IOHandle;
class Topic;
class rpc_man;

class NexioServer
{
public:

  struct Config
  {
    int port;
  };


  NexioServer(Config c);
  ~NexioServer();

  // start the event loop
  void start();
  void init();

  void new_start();

  void util_thread_tep();

  void new_client(IOHandle*);

  // TODO: decide on how topics are registered here, i.e., memory management
  void addTopic(Topic*);

  void add_rpc() {}

  void on_timer();

  TopicMan* topic_man() { return m_topicman.get(); }
  rpc_man* get_rpc_man() { return m_rpcman; }

private:

  void call_me( int );


  class Internal;
  friend class Internal;
  Internal * impl;


  Config m_config;
  event_loop m_evl;
  std::thread m_thread;
  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<TopicMan> m_topicman;
  IOLoop m_io_loop;
  rpc_man * m_rpcman;
  client_service *  m_clisvc;// the internal client
};


} // namespace

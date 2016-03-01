

#include "NexioServer.h"
#include "Table.h"
#include "Session.h"
#include "Logger.h"
#include "event_loop.h"
#include "client_service.h"
#include "dealer_service.h"

#include <Logger.h>

#include <sstream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <iostream>

#include <unistd.h>
#include <string.h>

XXX::NexioServer * server = nullptr;

XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eAll,
                                              true);

XXX::dealer_service * g_dealer = NULL;


int tep()
{
  auto __logptr = logger;
  _INFO_( "tep started" );

  sleep(3);

  XXX::Topic * topic = new XXX::Topic("T1");
  server -> addTopic( topic );

  XXX::Table * topictable = new XXX::Table("T2");
  server -> addTopic( topictable );

  std::vector<std::string> cols = {"health","status","post"};
  topictable->add_columns( cols );


  int rowid = 2;
  while (1)
  {
    sleep(1);

    rowid++;
    std::ostringstream os;
    os << "R_"  << rowid;

    topictable->update_row("r1", "f1", "v1");
    topictable->update_row(os.str(), "f1", "v1");
  }
  return 0;
}


std::mutex              g_active_session_mutex;
std::condition_variable g_active_session_condition;
XXX::session_handle g_sid;
bool g_active_session_notifed = false;

enum AdminEvent
{
  eNone,
  eRPCSent,
  eReplyReceived,
};

std::mutex              event_queue_mutex;
std::condition_variable event_queue_condition;
std::queue< AdminEvent > event_queue;


void call_cb(XXX::call_info& info, XXX::rpc_args& args, void* cb_user_data)
{
  auto __logptr = logger;
  const char* msg = ( const char* ) cb_user_data;

  _INFO_( "CALLER received reply in main, args="
          << args.args << ", cb_user_data: " << msg
          << ", reqid: " << info.reqid
          << ", proc:" << info.procedure );


  std::unique_lock< std::mutex > guard( event_queue_mutex );
  event_queue.push( eReplyReceived );
  event_queue_condition.notify_one();
}

void connect_cb_2(XXX::session_handle sh, int /*status*/, void* /* user */)
{
  std::lock_guard<std::mutex> guard(g_active_session_mutex);
  g_sid = sh;
  g_active_session_notifed = true;
  g_active_session_condition.notify_one();
}

class dealer_events : public XXX::dealer_listener
{
public:

  void rpc_registered(std::string uri)
  {
    // TODO: this is the code for rasing an RPC... temporary comented out for a test

    if (uri == "stop")
    {
      XXX::rpc_args args;
      jalson::json_array ja;
      ja.push_back( "hello" );
      ja.push_back( "world" );   //TODO: why do I not see thi value arrise at the other side? Jalson error?
      args.args = ja ;

      g_dealer->call_rpc("stop",
                         [](XXX::call_info& reqdet, XXX::rpc_args& args, void* cb_data)
                         { call_cb(reqdet, args, cb_data);},
                         args, (void*)"I_called_stop");

    }

    std::unique_lock< std::mutex > guard( event_queue_mutex );
    event_queue.push( eRPCSent );
    event_queue_condition.notify_one();
  }
};



int main(int /*argc*/, char** /*argv*/)
{
  auto __logptr = logger;

  /* new client service */
  dealer_events de;
  XXX::dealer_service d( logger, &de );
  g_dealer = &d;
  // start the internal thread of the client
  d.start();

  // sleep until main loop is ready
//  sleep(1);

  // XXX::dealer_service::Request req;
  // req.addr = "127.0.0.1";
  // req.port = 55555;
  // req.cb   = connect_cb;
  d.connect( "127.0.0.1", 55555, connect_cb_2, nullptr);

  // wait for a connection attempt to complete
  _INFO_("starting wait for a connection...");
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);
    // TODO: put in a time limit?
    g_active_session_condition.wait(guard,
                                    [](){ return g_active_session_notifed; } );
  }


  _INFO_("... wait complete");

  auto sp = g_sid.lock();
  if (!sp)
  {
    /* we failed to connect */
    _WARN_("failed to connect");
    return 1;
  }
  _INFO_( "got session, sid=" << *sp );


  auto wait_interval = std::chrono::seconds(5);

  bool keep_waiting = true;
  while (keep_waiting)
  {
    std::unique_lock< std::mutex > guard( event_queue_mutex );

    /*bool hasevent =*/ event_queue_condition.wait_for(guard, wait_interval,
                                                       [](){ return !event_queue.empty(); });

    if (event_queue.empty())
    {
      // TODO: eventually want to suppor tall kinds of errors, ie, no
      // connection, no rpc, no rpc reply etc
      std::cout << "timeout ... did not find the admin\n";

      return 1;
    }
    else while (!event_queue.empty())
    {
      AdminEvent aev = event_queue.front();
      event_queue.pop();

      switch (aev)
      {
        case eNone : break;
        case eRPCSent : break;  /* resets the timer */
        case eReplyReceived : keep_waiting = false; break;
      }
    }
  }

  return 0;
}

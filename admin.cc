

#include "NexioServer.h"
#include "Table.h"
#include "Session.h"
#include "Logger.h"
#include "event_loop.h"
#include "client_service.h"


#include <Logger.h>

#include <sstream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <iostream>

#include <unistd.h>
#include <string.h>

#include <getopt.h> /* for getopt_long; standard getopt is in unistd.h */

XXX::NexioServer * server = nullptr;

XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eAll,
                                              true);

std::unique_ptr<XXX::client_service> g_client;


struct user_options
{
    std::string addr;
    std::string port;
    std::string cmd;
    std::list< std::string > cmdargs;

    int verbose;

    user_options()
      : verbose(0)
    {
    }
} uopts;


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
  g_active_session_condition.notify_all();
}

// class dealer_events : public XXX::dealer_listener
// {
// public:

//   void rpc_registered(std::string uri)
//   {
//     // TODO: this is the code for rasing an RPC... temporary comented out for a test

//     if (uri == "stop")
//     {
//       XXX::rpc_args args;
//       jalson::json_array ja;
//       ja.push_back( "hello" );
//       ja.push_back( "world" );   //TODO: why do I not see thi value arrise at the other side? Jalson error?
//       args.args = ja ;


//     }

//     std::unique_lock< std::mutex > guard( event_queue_mutex );
//     event_queue.push( eRPCSent );
//     event_queue_condition.notify_one();
//   }
// };


static void die(const char* e)
{
  std::cout << e  << std::endl;
  exit( 1 );
}

static void usage()
{
  exit(0);
}

static void version()
{
//  std::cout << PACKAGE_VERSION << std::endl;  exit(0)l
  exit(0);
}

static void process_options(int argc, char** argv)
{
/*
  struct option
  {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
  };
*/

//  int digit_optind = 0;
  static struct option long_options[] = {
    {"help",    no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {NULL, 0, NULL, 0}
  };
  const char* optstr="hvd:";

  ::opterr=1;

  while (true)
  {
    /* "optind" is the index of the next element to be processed in argv.  It
       is defined in the getopts header, and the system initializes this value
       to 1.  The caller can reset it to 1 to restart scanning of the same
       argv, or when scanning a new argument vector. */

    // take a copy to remember value for after return from getopt_long()
    //int this_option_optind = ::optind ? ::optind : 1;
    int long_index = 0;

    int c = getopt_long(argc, argv,
                        optstr,
                        long_options, &long_index);
    if (c == -1) break;

    switch(c)
    {
      case  0  : /* got long option */; break;
      case 'd' : uopts.verbose++; break;
      case 'h' : usage();
      case 'v' : version();
      case '?' : exit(1); // invalid option
      default:
      {
        std::cout << "getopt_long() returned (dec) " << (unsigned int)(c) << "\n";
        exit(1);
      }
    }
  } //while

  if (optind < argc) uopts.addr = argv[optind++];
  if (optind < argc) uopts.port = argv[optind++];
  if (optind < argc) uopts.cmd  = argv[optind++];
  while (optind < argc) uopts.cmdargs.push_back(argv[optind++]);
}

int main(int argc, char** argv)
{
  process_options(argc, argv);
  auto __logptr = logger;

  /* new client service */
//  dealer_events de;

  XXX::client_service::config config;
  config.port = 0;
  g_client.reset( new XXX::client_service(logger, config) );


  g_client->start();

  g_client->connect( "127.0.0.1", 55555, connect_cb_2, nullptr);

  // wait for a connection attempt to complete

  auto wait_interval = std::chrono::seconds(7);
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        wait_interval,
                                                        [](){ return g_active_session_notifed; });
    if (!hasevent)
    {
      std::cout << "no connection\n";
      return 1;
    }
  }
  if (!g_sid.lock())
  {
    std::cout << "no connection\n";
    return 1;
  }

  _INFO_("GOT CONNECTION");
  sleep(5);
  XXX::rpc_args args;
  jalson::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );
  args.args = ja ;


  std::cout << "making CALL\n";
  XXX::t_client_request_id callreqid = g_client->call_rpc(g_sid,
                                                          "stop", args,
                                                          [](XXX::call_info& reqdet,
                                                             XXX::rpc_args& args,
                                                             void* cb_data)
                                                          { call_cb(reqdet, args, cb_data);},
                                                          (void*)"I_called_stop");


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

  //while (1)   sleep(1);

  g_client.reset();
  delete logger;
  return 0;
}

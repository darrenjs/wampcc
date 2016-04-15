

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



XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eInfo,
                                              true);

std::unique_ptr<XXX::client_service> g_client;


struct user_options
{
    std::string addr;
    std::string port;
    std::string cmd;
    std::list< std::string > cmdargs;
    std::list< std::string > subscribe_topics;

    int verbose;

    user_options()
      : verbose(0)
    {
    }
} uopts;

//----------------------------------------------------------------------
std::string util_strerror(int e)
{
  std::string retval;

  char errbuf[256];
  memset(errbuf, 0, sizeof(errbuf));

/*

TODO: here I should be using the proper feature tests for the XSI
implementation of strerror_r .  See man page.

  (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE

*/

#ifdef _GNU_SOURCE
  // the GNU implementation might not write to errbuf, so instead, always use
  // the return value.
  return ::strerror_r(e, errbuf, sizeof(errbuf)-1);
#else
  // XSI implementation
  if (::strerror_r(e, errbuf, sizeof(errbuf)-1) == 0)
    return errbuf;
#endif

  return "unknown";
}


std::mutex              g_active_session_mutex;
std::condition_variable g_active_session_condition;
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


void subscribe_cb(XXX::subscription_event_type evtype,
                  const std::string&,
                  const jalson::json_value& args,
                  void* /*user*/)
{
  std::cout << "received topic update!!! evtype: " << evtype << ", args: " << args << "\n";
}
int g_connect_status = 0;

void connect_cb_2(XXX::router_conn* /*router_session*/,
                  int status,
                  bool /*is_open*/)
{
  std::lock_guard<std::mutex> guard(g_active_session_mutex);

  g_connect_status = status;

  g_active_session_notifed = true;
  g_active_session_condition.notify_all();
}


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
    {"subscribe", required_argument, 0, 's'},
    {NULL, 0, NULL, 0}
  };
  const char* optstr="hvds:";

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
      case 's' : uopts.subscribe_topics.push_back(optarg); break;
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

  XXX::client_service::config config;
  config.port = 0;
  config.realm = "default_realm";
  g_client.reset( new XXX::client_service(logger, config) );

  g_client->start();

  XXX::router_conn rconn( g_client.get(), connect_cb_2, nullptr );

  rconn.connect("127.0.0.1", 55555);

  // wait for a connection attempt to complete
  auto wait_interval = std::chrono::seconds(7);
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        wait_interval,
                                                        [](){ return g_active_session_notifed; });
    if (!hasevent) die("no connection");
  }

  if (g_connect_status != 0)
  {
    std::cout << "Unable to connect, error " << g_connect_status
              << ": " << util_strerror(g_connect_status) << "\n";
    exit(1);
  }


  XXX::rpc_args args;
  jalson::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );
  args.args = ja ;


  rconn.call("stop", args,
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

    rconn.subscribe("topic1", subscribe_cb, nullptr);

    while (!event_queue.empty())
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

  while (1) sleep(1);

  g_client.reset();
  delete logger;
  return 0;
}

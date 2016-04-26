
#include "Session.h"
#include "Logger.h"
#include "event_loop.h"
#include "client_service.h"
#include "Topic.h"


#include <Logger.h>

#include <sstream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <list>
#include <iostream>

#include <unistd.h>
#include <string.h>

#include <sys/time.h>

#include <getopt.h> /* for getopt_long; standard getopt is in unistd.h */



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
  std::list< std::string > subscribe_topics;

  std::string publish_topic;
  std::string publish_message;

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


void call_cb(XXX::call_info& info, jalson::json_object& details, XXX::wamp_args& args, void* cb_user_data)
{
  auto __logptr = logger;
  const char* msg = ( const char* ) cb_user_data;

  _INFO_( "CALLER received reply in main, args="
          << args.args_list << ", cb_user_data: " << msg
          << ", reqid: " << info.reqid
          << ", proc:" << info.procedure );


  std::unique_lock< std::mutex > guard( event_queue_mutex );
  event_queue.push( eReplyReceived );
  event_queue_condition.notify_one();
}

/* called upon subscribed and update events */
void subscribe_cb(XXX::subscription_event_type evtype,
                  const std::string& uri,
                  const jalson::json_object& details,
                  const jalson::json_array& args_list,
                  const jalson::json_object& args_dict,
                  void* /*user*/)
{
  std::cout << "received topic update!!! evtype: " << evtype << ", args_list: " << args_list
            << ", args_dict:" << args_dict << "\n";
}
int g_connect_status = 0;


void router_connection_cb(XXX::router_conn* /*router_session*/,
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
    {"help",      no_argument, 0, 'h'},
    {"version",   no_argument, 0, 'v'},
    {"subscribe", required_argument, 0, 's'},
    {"publish",   required_argument, 0, 'p'},
    {"msg",       required_argument, 0, 'm'},
    {NULL, 0, NULL, 0}
  };
  const char* optstr="hvds:p:m:";

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
      case 'p' : uopts.publish_topic = optarg; break;
      case 'm' : uopts.publish_message = optarg; break;
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

std::string get_timestamp()
{

  // get current time
  timeval now;
  struct timezone * const tz = NULL; /* not used on Linux */
  gettimeofday(&now, tz);

  struct tm _tm;
  localtime_r(&now.tv_sec, &_tm);

  std::ostringstream os;
  os << _tm.tm_hour << ":" << _tm.tm_min << ":" << _tm.tm_sec;

  return os.str();
}


int main(int argc, char** argv)
{
  process_options(argc, argv);


  XXX::client_service::config config;
  config.server_port = 0;
  config.realm = "default_realm";
  g_client.reset( new XXX::client_service(logger, config) );

  //std::unique_ptr<XXX::text_topic> topic;

  // if (!uopts.publish_topic.empty())
  //   topic.reset( new XXX::text_topic( uopts.publish_topic ) );

  // if (topic) g_client->add_topic( topic.get() );

  g_client->start();

  XXX::router_conn rconn( g_client.get(), router_connection_cb, nullptr );

  rconn.connect("127.0.0.1", 55555);

  // wait for a connection attempt to complete
  auto wait_interval = std::chrono::seconds(5);
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        wait_interval,
                                                        [](){ return g_active_session_notifed; });

    if (!hasevent) die("failed to obtain remote connection");
  }

  if (g_connect_status != 0)
  {
    std::cout << "Unable to connect, error " << g_connect_status
              << ": " << util_strerror(g_connect_status) << "\n";
    exit(1);
  }


  // TODO: take CALL parameters from command line
  XXX::wamp_args args;
  jalson::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );
  args.args_list = ja ;

  rconn.call("stop", args,
             [](XXX::call_info& reqdet,
                jalson::json_object options,
                XXX::wamp_args& args,
                void* cb_data)
             { call_cb(reqdet, options, args, cb_data);},
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

    for (auto & topic : uopts.subscribe_topics)
      rconn.subscribe(topic, subscribe_cb, nullptr);

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


  // topic publication - basic WAMP style publish
  if (!uopts.publish_topic.empty())
  {
    jalson::json_array args_list;
    args_list.push_back(uopts.publish_message);
    g_client->publish_all(true,
                          uopts.publish_topic,
                          jalson::json_object(),
                          args_list,
                          jalson::json_object());
  }
  //if (topic) topic->update( uopts.publish_message.c_str() );


  while (1) sleep(1);

  g_client.reset();
  delete logger;
  return 0;
}

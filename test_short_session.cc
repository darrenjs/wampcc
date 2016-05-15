
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

  std::string register_procedure;
  std::string call_procedure;

  int verbose;

  user_options()
    : verbose(0)
  {
  }
} uopts;



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



int g_connect_status = 0;


void router_connection_cb(XXX::router_conn* /*router_session*/,
                          int errcode,
                          bool is_open)
{
  std::lock_guard<std::mutex> guard(g_active_session_mutex);

  auto __logptr = logger;
  _INFO_ ("router connection is " << (is_open? "open" : "closed") << ", errcode " << errcode);

  g_connect_status = errcode;
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
    {"register",  required_argument, 0, 'r'},
    {"call",      required_argument, 0, 'c'},
    {"msg",       required_argument, 0, 'm'},
    {NULL, 0, NULL, 0}
  };
  const char* optstr="hvds:p:m:r:c:";

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
      case 'r' : uopts.register_procedure = optarg; break;
      case 'c' : uopts.call_procedure = optarg; break;
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

  g_client.reset( new XXX::client_service(logger) );

  g_client->start();


  XXX::router_conn * rconn = new XXX::router_conn( g_client.get(),  "default_realm", router_connection_cb, nullptr );

  rconn->connect("127.0.0.1", 55555);
  std::cout << "deleting router_conn\n";
  delete rconn;
  memset(rconn,0,sizeof(XXX::router_conn));
  std::cout << "router_conn deletion complete\n";
  sleep(100);

  g_client.reset();
  delete logger;
  return 0;
}

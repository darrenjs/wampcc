
#include "Logger.h"
#include "event_loop.h"
#include "client_service.h"
#include "kernel.h"
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


std::shared_ptr<XXX::router_conn> rconn;

XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eAll,
                                              true);

std::unique_ptr<XXX::kernel> g_client;


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


struct callback_t
{
  callback_t(XXX::kernel* s, const char* d)
    : svc(s),
      request(d)
  {
  }
  XXX::kernel* svc;
  const char* request;
};
void procedure_cb(XXX::invoke_details& invocation)
{
  const callback_t* cbdata = (callback_t*) invocation.user;

  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< invocation.uri << "' invoked, args: " << invocation.args.args_list
          << ", user:" << cbdata->request );

  // example of making a call back into the connection object during a callback
  rconn->publish("call", jalson::json_object(), XXX::wamp_args());

  auto my_args =  invocation.args;

  my_args.args_list = jalson::json_array();
  jalson::json_array & arr = my_args.args_list.as_array();
  arr.push_back("hello");
  arr.push_back("back");

  invocation.yield_fn(my_args);

  // now delete
  // std::cout << "deleting this connection from user space\n";
  // rconn.reset();
}

void call_cb(XXX::wamp_call_result r)
{
  auto __logptr = logger;
  const char* msg = ( const char* ) r.user;

  if (r.was_error)
  {
    _INFO_( "received error, error=" << r.error_uri << ", args="
            << r.args.args_list << ", cb_user_data: " << msg
            << ", reqid: " << r.reqid
            << ", proc:" << r.procedure );
  }
  else
  {
    _INFO_( "received result, args="
            << r.args.args_list << ", cb_user_data: " << msg
            << ", reqid: " << r.reqid
            << ", proc:" << r.procedure );
  }
  std::unique_lock< std::mutex > guard( event_queue_mutex );
  event_queue.push( eReplyReceived );
  event_queue_condition.notify_one();
}

/* called upon subscribed and update events */
void subscribe_cb(XXX::subscription_event_type evtype,
                  const std::string& /* uri */,
                  const jalson::json_object& /* details */,
                  const jalson::json_array& args_list,
                  const jalson::json_object& args_dict,
                  void* /*user*/)
{
  std::cout << "received topic update!!! evtype: " << evtype << ", args_list: " << args_list
            << ", args_dict:" << args_dict << "\n";
}
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

  if (!is_open)
  {
    _INFO_("Deleting the router-connection object");
    rconn.reset();
  }
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

  g_client.reset( new XXX::kernel(logger) );

  //std::unique_ptr<XXX::text_topic> topic;

  // if (!uopts.publish_topic.empty())
  //   topic.reset( new XXX::text_topic( uopts.publish_topic ) );

  // if (topic) g_client->add_topic( topic.get() );

  g_client->start();

  rconn.reset(
    new XXX::router_conn(g_client.get(),  "default_realm", router_connection_cb, nullptr )
    );

  rconn->connect("127.0.0.1", 55555);
//  rconn.connect("10.255.255.1", 55555);

  // wait for a connection attempt to complete
  auto wait_interval = std::chrono::seconds(50);
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

  bool long_wait = false;
  bool wait_reply = false;


  // now that we are connected, make our requests


  // subscribe
  if (! uopts.subscribe_topics.empty()) long_wait = true;
  for (auto & topic : uopts.subscribe_topics)
    rconn->subscribe(topic, jalson::json_object(), subscribe_cb, nullptr);

  // register
  std::unique_ptr<callback_t> cb1( new callback_t(g_client.get(),"my_hello") );
  if (!uopts.register_procedure.empty())
  {
    rconn->provide(uopts.register_procedure,
                   jalson::json_object(),
                  procedure_cb,
                   (void*) cb1.get());
    long_wait = true;
  }

  // publish
  if (!uopts.publish_topic.empty())
  {
    XXX::wamp_args pub_args;
    pub_args.args_list = jalson::json_value::make_array();
    pub_args.args_list.as_array().push_back(uopts.publish_message);
    rconn->publish(uopts.publish_topic,
                   jalson::json_object(),
                   pub_args);
  }

  // call
  if (!uopts.call_procedure.empty())
  {
    rconn->call(uopts.call_procedure,
                jalson::json_object(),
                args,
                [](XXX::wamp_call_result r)
                { call_cb(r);},
                (void*)"I_called_the_proc");
    wait_reply = true;
  }



  while (long_wait || wait_reply)
  {
    std::unique_lock< std::mutex > guard( event_queue_mutex );

    /*bool hasevent =*/ event_queue_condition.wait_for(guard, wait_interval,
                                                       [](){ return !event_queue.empty(); });

    // if (event_queue.empty())
    // {
    //   // TODO: eventually want to suppor tall kinds of errors, ie, no
    //   // connection, no rpc, no rpc reply etc
    //   std::cout << "timeout ... did not find the admin\n";

    //   break;
    // }

    while (!event_queue.empty())
    {
      AdminEvent aev = event_queue.front();
      event_queue.pop();

      switch (aev)
      {
        case eNone : break;
        case eRPCSent : break;  /* resets the timer */
        case eReplyReceived : wait_reply = false; ;break;
      }
    }

  }

  sleep(1); // TODO: think I need this, to give publish time to complete
  rconn.reset();

  // remember to free the kernel and logger after all sessions are closed
  // (sessions might attempt logging during their destruction)
  g_client.reset();
  delete logger;
  return 0;
}

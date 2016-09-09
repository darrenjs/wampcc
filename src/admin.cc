
#include "XXX/event_loop.h"
#include "XXX/kernel.h"
#include "XXX/topic.h"
#include "XXX/io_loop.h"
#include "XXX/io_handle.h"
#include "XXX/io_connector.h"
#include "XXX/wamp_session.h"
#include "XXX/websocket_protocol.h"
#include "XXX/rawsocket_protocol.h"

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


auto __logger = XXX::logger::stdlog(std::cout,
                                    XXX::logger::levels_upto(XXX::logger::eInfo), 1);


std::unique_ptr<XXX::kernel> g_kernel;


struct user_options
{
  std::string username;
  std::string password;
  std::string realm;

  std::string addr;
  std::string port;
  std::string cmd;
  std::list< std::string > cmdargs;
  std::list< std::string > subscribe_topics;

  std::string publish_topic;
  std::string publish_message;

  std::string register_procedure;
  std::string call_procedure;

  int verbose = 0;
  bool no_uri_check = false;

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


void procedure_cb(XXX::wamp_invocation& invocation)
{
  const callback_t* cbdata = (callback_t*) invocation.user;

  /* called when a procedure within a CALLEE is triggered */

  std::cout << "CALLEE has procuedure_cb invoked, args: " << invocation.args.args_list
            << ", user:" << cbdata->request;

  // rconn->publish("call", jalson::json_object(), XXX::wamp_args());

  auto my_args =  invocation.args;

  my_args.args_list = jalson::json_array();
  jalson::json_array & arr = my_args.args_list.as_array();
  arr.push_back("hello");
  arr.push_back("back");

  invocation.yield(my_args);
}

void call_cb(XXX::wamp_call_result r)
{

  const char* msg = ( const char* ) r.user;

  if (r.was_error)
  {
    std::cout << "received error, error=" << r.error_uri << ", args="
              << r.args.args_list << ", cb_user_data: " << msg
              << ", reqid: " << r.reqid
              << ", proc:" << r.procedure ;
  }
  else
  {
    std::cout << "received result, args="
              << r.args.args_list << ", cb_user_data: " << msg
              << ", reqid: " << r.reqid
              << ", proc:" << r.procedure;
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

bool g_handshake_success = false;

void router_connection_cb(int errcode,
                          bool is_open)
{
  std::lock_guard<std::mutex> guard(g_active_session_mutex);

  if (!is_open)
    std::cout << "WAMP session closed, errcode " << errcode << std::endl;
  else
    g_handshake_success = true;

  g_active_session_notifed = true;
  g_active_session_condition.notify_all();
}


static void die(std::string e)
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

  enum
  {
    NO_URI_CHECK = 1
  };

//  int digit_optind = 0;
  static struct option long_options[] = {
    {"help",      no_argument, 0, 'h'},
    {"version",   no_argument, 0, 'v'},
    {"subscribe", required_argument, 0, 's'},
    {"publish",   required_argument, 0, 'p'},
    {"register",  required_argument, 0, 'r'},
    {"call",      required_argument, 0, 'c'},
    {"msg",       required_argument, 0, 'm'},
    {"username",  required_argument, 0, 'U'},
    {"password",  required_argument, 0, 'P'},
    {"realm",     required_argument, 0, 'R'},
    {"no-uri-check", no_argument , 0, NO_URI_CHECK},
    {NULL, 0, NULL, 0}
  };
  const char* optstr="hvds:p:m:r:c:U:P:R:";

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
      case 0: /* got long option */ break;
      case NO_URI_CHECK : uopts.no_uri_check = true; break;
      case 'd' : uopts.verbose++; break;
      case 'h' : usage();
      case 'v' : version();
      case 's' : uopts.subscribe_topics.push_back(optarg); break;
      case 'p' : uopts.publish_topic = optarg; break;
      case 'm' : uopts.publish_message = optarg; break;
      case 'r' : uopts.register_procedure = optarg; break;
      case 'c' : uopts.call_procedure = optarg; break;
      case 'U' : uopts.username = optarg; break;
      case 'P' : uopts.password = optarg; break;
      case 'R' : uopts.realm    = optarg; break;
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

  // check topics
  if (uopts.no_uri_check == false)
  {
    XXX::uri_regex uri_check;
    for (auto & i : uopts.subscribe_topics)
      if (not uri_check.is_strict_uri(i.c_str()))
        die("not strict uri: " + i);
  }

  if (uopts.username.empty()) die("missing username");
  if (uopts.password.empty()) die("missing password");
  if (uopts.realm.empty())    die("missing realm");
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

  g_kernel.reset( new XXX::kernel({}, __logger));
  g_kernel->start();

  /* Create a socket connector.  This will immediately make an attempt to
   * connect to the target end point.  The connector object is a source of async
   * events (the connect and disconnect call back), and so must be managed
   * asynchronously. */
  std::shared_ptr<XXX::io_connector> conn
    = g_kernel->get_io()->add_connection("t420", "55555", false);

  auto connect_fut = conn->get_future();

  std::unique_ptr<XXX::io_handle> up_handle;
  try
  {
    /* Wait until the connector has got a result. The result can be successful,
     * in which case a socket is available, or result could be a failure, in
     * which case either an exception will be available or a null pointer. */
    std::future_status status;
    do
    {
      status = connect_fut.wait_for(std::chrono::seconds(5));

      if (status == std::future_status::timeout)
      {
        std::cout << "timed out when trying to connect, cancelling" << std::endl;
        conn->async_cancel();
      }
    } while (status != std::future_status::ready);

    /* A result is available; our socket connection could be available. */
    up_handle = connect_fut.get();
    if (!up_handle)
    {
      std::cout << "connect failed\n";
      return 1;
    }
  }
  catch (std::exception & e)
  {
    std::cout << "connect failed : " << e.what() << std::endl;
    return 1;
  }


  XXX::client_credentials credentials;
  credentials.realm  = uopts.realm;
  credentials.authid = uopts.username;
  credentials.authmethods = {"wampcra"};
  credentials.secret_fn = [=]() -> std::string { return uopts.password; };

  /* We have obtained a socket. It's not yet being read from. We now create a
   * wamp_session that takes ownership of the socket, and initiates socket read
   * events. The wamp_session will commence the WAMP handshake; connection
   * success is delivered via the callback. */

  auto fn = [](XXX::session_handle wp, bool is_open){
    if (auto sp = wp.lock())
      router_connection_cb(0, is_open);
  };


  XXX::rawsocket_protocol::options options;
  std::shared_ptr<XXX::wamp_session> ws (
    XXX::wamp_session::create<XXX::rawsocket_protocol>(*g_kernel.get(),
                                                       std::move(up_handle),
                                                       fn, options)
    );

  ws->initiate_hello(credentials);

  /* Wait for the WAMP session to authenticate and become open */
  auto wait_interval = std::chrono::seconds(50);
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        wait_interval,
                                                        [](){ return g_active_session_notifed; });

    if (!hasevent) die("failed to obtain remote connection");
  }

  if (!g_handshake_success)
    die("Unable to connect");

  /* WAMP session is now open  */

  std::cout << "WAMP session open" << std::endl;

  // TODO: take CALL parameters from command line
  XXX::wamp_args args;
  jalson::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );
  args.args_list = ja ;

  bool long_wait = false;
  bool wait_reply = false;


  XXX::basic_list my_list;

  XXX::basic_list::list_events obs;
  auto displayer = [&my_list]()
    {
      jalson::json_array value = my_list.copy_value();
      std::cout << "list: ";
      for (auto & item : value)
        std::cout << item << ",";
      std::cout << std::endl;
    };
  obs.on_insert = [&my_list, displayer](size_t, const jalson::json_value&) {displayer();};
  obs.on_replace = [&my_list, displayer](size_t, const jalson::json_value&) {displayer();};
  obs.on_erase = [&my_list, displayer](size_t) {displayer();};
  obs.on_reset = [&my_list, displayer](const XXX::basic_list::internal_impl&) {displayer();};
  my_list.add_observer(obs);


  // XXX::basic_list_subscription_handler<XXX::basic_list>  h2( my_list );
  // XXX::model_subscription< XXX::basic_list_subscription_handler<XXX::basic_list> >
  //   sub_planets2(ws, "planets", h2 );

  XXX::model_subscription< XXX::basic_list_subscription_handler<> >
    sub_planets3(ws, "planets", my_list);


  // subscribe to user topics
  jalson::json_object sub_options { {KEY_PATCH, 1} };
  if (! uopts.subscribe_topics.empty()) long_wait = true;
  for (auto & topic : uopts.subscribe_topics)
    ws->subscribe(topic, sub_options, subscribe_cb, nullptr);

  // register
  std::unique_ptr<callback_t> cb1( new callback_t(g_kernel.get(),"my_hello") );
  if (!uopts.register_procedure.empty())
  {
    ws->provide(uopts.register_procedure,
                   jalson::json_object(),
                  procedure_cb,
                   (void*) cb1.get());
    long_wait = true;
  }

  // publish
  if (!uopts.publish_topic.empty())
  {
    // XXX::wamp_args pub_args;
    // pub_args.args_list = jalson::json_value::make_array();
    // pub_args.args_list.as_array().push_back(uopts.publish_message);
    // ws->publish(uopts.publish_topic,
    //             jalson::json_object(),
    //             pub_args);

    // XXX::basic_text_model tm;
    // XXX::topic publisher(uopts.publish_topic, &tm);
    // publisher.add_wamp_session(ws);

    // tm.set_value("hello world");
  }

  // call
  if (!uopts.call_procedure.empty())
  {
    ws->call(uopts.call_procedure,
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


  /* Commence orderly shutdown of the wamp_session.  Shutdown is an asychronous
   * operation so we start the request and then wait for the request to
   * complete.  Once complete, we shall not receive anymore events from the
   * wamp_session object (and thus is safe to delete). */

  auto fut_closed = ws->close();
  fut_closed.wait();
  ws.reset();


  /* We must be mindful to free the kernel and logger only after all sessions
     are closed (e.g. sessions might attempt logging during their
     destruction) */

  g_kernel.reset();


  return 0;
}

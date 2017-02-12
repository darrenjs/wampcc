#include "XXX/kernel.h"
#include "XXX/utils.h"
#include "XXX/data_model.h"
#include "XXX/wamp_session.h"
#include "XXX/tcp_socket.h"
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


// replace with optional<> if C++17 present
template <typename T> struct user_optional
{
  user_optional& operator=(T v)
  {
    m_value.first = std::move(v);
    m_value.second = true;
    return *this;
  }
  constexpr T& value() const { return m_value.first; }
  T& value() { return m_value.first; }
  constexpr operator bool() const { return m_value.second; }
private:
  std::pair<T,bool> m_value;
};


struct user_options
{
  std::string username;
  std::string password;
  std::string realm;

  user_optional<std::string> addr;
  user_optional<std::string> port;

  std::list< std::string > subscribe_topics;

  std::string publish_topic;

  std::string call_procedure;

  int verbose = 0;
  bool no_uri_check = false;

  std::string arg_list;
  std::string arg_dict;
} uopts;


std::mutex              g_active_session_mutex;
std::condition_variable g_active_session_condition;
bool g_active_session_notifed = false;

enum AdminEvent
{
  eNone,
  eRPCSent,
  eReplyReceived,
  eClosed
};

std::mutex               event_queue_mutex;
std::condition_variable  event_queue_condition;
std::queue< AdminEvent > event_queue;


struct t_callback
{
  t_callback(XXX::kernel* s, const char* d)
    : svc(s),
      request(d)
  {
  }
  XXX::kernel* svc;
  const char* request;
};


void rpc_call_cb(XXX::wamp_call_result r)
{
  const char* msg = ( const char* ) r.user;

  if (r.was_error)
  {
    std::cout << "received error, " << r.error_uri << ", args="
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
  std::lock_guard< std::mutex > guard( event_queue_mutex );
  event_queue.push( eReplyReceived );
  event_queue_condition.notify_one();
}

/* called upon subscribed and update events */
void subscribe_cb(XXX::wamp_subscription_event ev)
{
  std::cout << "topic update: subscription_id: " << ev.subscription_id << ", args_list: " << ev.args.args_list
            << ", args_dict:" << ev.args.args_dict << "\n";
}

bool g_handshake_success = false;

void session_state_cb(bool is_open)
{
  std::lock_guard<std::mutex> guard(g_active_session_mutex);

  if (!is_open)
  {
    std::cout << "wamp session closed" << std::endl;
    std::lock_guard< std::mutex > guard( event_queue_mutex );
    event_queue.push( eClosed );
    event_queue_condition.notify_one();
  }
  else
    g_handshake_success = true;

  g_active_session_notifed = true;
  g_active_session_condition.notify_all();
}


static void die(std::string e)
{
  std::cout << e << std::endl;
  exit( 1 );
}


static void usage()
{
  std::cout << "usage: admin [OPTIONS] ADDRESS PORT" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -U, --username=ARG"     << "\t\t" << "specify a session username" << std::endl;
  std::cout << "  -P, --password=ARG"     << "\t\t" << "specify a session password" << std::endl;
  std::cout << "  -R, --realm=ARG"        << "\t\t" << "specify a session realm" << std::endl;
  std::cout << "  -s, --subscribe=URI"    << "\t\t" << "subscribe to topic" << std::endl;
  std::cout << "  -p, --publish=URI"      << "\t\t" << "publish to topic" << std::endl;
  //std::cout << "  -r, -register=URI"     << "\t\t" << "register procedure" << std::endl;
  std::cout << "  -c, --call=URI"         << "\t\t" << "call procedure" << std::endl;
  std::cout << "  --arglist=ARG"          << "\t\t\t" << "wamp argument list, ARG is a JSON array" << std::endl;
  std::cout << "  --argdict=ARG"          << "\t\t\t" << "wamp argument dictionary, ARG is a JSON object" << std::endl;

  std::cout << "  -h, -help"              << "\t\t\t" << "display this help" << std::endl;
  std::cout << "  -v, --version"          << "\t\t\t" << "print program version" << std::endl;

  std::cout << std::endl << "Examples:" <<std::endl;
  std::cout << std::endl << "Call a procedure with JSON argument as array and object" << std::endl;
  std::cout << "  admin -U peter -P secret2 -R public -c set_color --arglist '[\"green\", \"light\"]'"   << std::endl;
  std::cout << "  admin -U peter -P secret2 -R public -c set_color --argdict '{\"foreground\" : \"red\"}'" << std::endl;

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

  // these enums are used for options that don't have a short version
  enum
  {
    NO_URI_CHECK = 1,
    ARGLIST,
    ARGDICT
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
    {"arglist",   required_argument, 0, ARGLIST},
    {"argdict",   required_argument, 0, ARGDICT},
    {"no-uri-check", no_argument ,   0, NO_URI_CHECK},
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
      case ARGLIST : uopts.arg_list = optarg; break;
      case ARGDICT : uopts.arg_dict = optarg; break;
      case 'd' : uopts.verbose++; break;
      case 'h' : usage();
      case 'v' : version();
      case 's' : uopts.subscribe_topics.push_back(optarg); break;
      case 'p' : uopts.publish_topic = optarg; break;
      case 'c' : uopts.call_procedure = optarg; break;
      case 'U' : uopts.username = optarg; break;
      case 'P' : uopts.password = optarg; break;
      case 'R' : uopts.realm    = optarg; break;
      case '?' : exit(1); // invalid option
      default:
      {
        std::cout << "unknown option: -" << char(c) << "\n";
        exit(1);
      }
    }
  } //while

  if (optind < argc) uopts.addr = argv[optind++];
  if (optind < argc) uopts.port = argv[optind++];


  if (!uopts.addr) die("missing address");
  if (!uopts.port) die("missing port");

  // check topics
  if (uopts.no_uri_check == false)
  {
    XXX::uri_regex uri_check;
    for (auto & i : uopts.subscribe_topics)
      if (not uri_check.is_strict_uri(i.c_str()))
        die("not strict uri: " + i);
  }

  if (uopts.username.empty()) die("missing username");
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


int main_impl(int argc, char** argv)
{
  process_options(argc, argv);

  // take CALL parameters from command line
  XXX::wamp_args args;
  if (!uopts.arg_list.empty())
  {
    try
    {
      auto jv = jalson::decode(uopts.arg_list.c_str(), uopts.arg_list.size());
      if (!jv.is_array())
        throw std::runtime_error("expected JSON array");
      args.args_list = jv.as_array();
    }
    catch (std::exception& e)
    {
      throw std::runtime_error(std::string("invalid arglist parameter, ") + e.what());
    }
  }
  if (!uopts.arg_dict.empty())
  {
    try
    {
      auto jv = jalson::decode(uopts.arg_dict.c_str(), uopts.arg_dict.size());
      if (!jv.is_object())
        throw std::runtime_error("expected JSON object");
      args.args_dict = jv.as_object();
    }
    catch (std::exception& e)
    {
      throw std::runtime_error(std::string("invalid argdict parameter, ") + e.what());
    }
  }

  /* Setup XXX core components */


  XXX::logger console_logger {
    [](XXX::logger::Level l){ return l <= XXX::logger::eWarn;; },
    [](XXX::logger::Level, const std::string& msg, const char*, int){
      std::cout << msg << std::endl;
    }
  };

  std::unique_ptr<XXX::kernel> g_kernel( new XXX::kernel({}, console_logger));

  std::unique_ptr<XXX::tcp_socket> sock( new XXX::tcp_socket(g_kernel.get()) );

  std::future_status status;

  /* Make an attempt to connect to the target end point */
  auto fut = sock->connect(uopts.addr.value(), atoi(uopts.port.value().c_str()));

  /* Wait for a connection result */
  status = fut.wait_for(std::chrono::seconds(3));

  if (status == std::future_status::deferred)
    throw std::runtime_error("unexpected deffered connect");

  if (status == std::future_status::timeout)
    throw std::runtime_error("time-out during connect");

  if (status == std::future_status::ready)
  {
    XXX::uverr ec = fut.get();
    if (ec)
      die("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());
  }

  /* A result is available; our socket connection could be available. */

  if (!sock->is_connected())
    throw std::runtime_error("socket not connected");

  XXX::rawsocket_protocol::options proto_opts;
  std::shared_ptr<XXX::wamp_session> ws =
    XXX::wamp_session::create<XXX::rawsocket_protocol>(
      g_kernel.get(),
      std::move(sock),
      [](XXX::session_handle wp, bool is_open) {
        if (auto sp = wp.lock())
          session_state_cb(is_open);
      }, proto_opts);

  if (!ws)
    throw std::runtime_error("failed to obtain wamp session");

  XXX::client_credentials credentials;
  credentials.realm  = uopts.realm;
  credentials.authid = uopts.username;
  credentials.authmethods = {"wampcra"};
  credentials.secret_fn = [=]() -> std::string { return uopts.password; };

  ws->initiate_hello(credentials);

  /* Wait for the WAMP session to authenticate and become open */
  auto wait_interval = std::chrono::seconds(50);
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        wait_interval,
                                                        [](){ return g_active_session_notifed; });

    if (!hasevent)
      throw std::runtime_error("timeout when establishing wamp session");
  }

  if (!g_handshake_success)
    throw std::runtime_error("wamp session could not be established");

  /* WAMP session is now open  */

  std::cout << "wamp session open" << std::endl;

  bool long_wait = false;
  bool wait_reply = false;

  // XXX::basic_list my_list;
  // XXX::basic_list::list_events obs;
  // auto displayer = [&my_list]()
  //   {
  //     jalson::json_array value = my_list.copy_value();
  //     std::cout << "list: ";
  //     for (auto & item : value)
  //       std::cout << item << ",";
  //     std::cout << std::endl;
  //   };
  // obs.on_insert = [&my_list, displayer](size_t, const jalson::json_value&) {displayer();};
  // obs.on_replace = [&my_list, displayer](size_t, const jalson::json_value&) {displayer();};
  // obs.on_erase = [&my_list, displayer](size_t) {displayer();};
  // obs.on_reset = [&my_list, displayer](const XXX::basic_list::internal_impl&) {displayer();};
  // my_list.add_observer(obs);



  // subscribe to user topics
  XXX::subscribed_cb scb; // TODO:
  jalson::json_object sub_options { {KEY_PATCH, 1} };
  if (! uopts.subscribe_topics.empty()) long_wait = true;
  for (auto & topic : uopts.subscribe_topics)
    ws->subscribe(topic, sub_options, scb, subscribe_cb, nullptr);


  // publish
  if (!uopts.publish_topic.empty())
  {
    ws->publish(uopts.publish_topic,
                jalson::json_object(),
                args);

    // XXX::basic_text_model tm;
    // XXX::topic publisher(uopts.publish_topic, &tm);
    // publisher.add_wamp_session(ws);

    // tm.set_value("hello world");
  }

  // call a remote procedure
  if (!uopts.call_procedure.empty())
  {
    ws->call(uopts.call_procedure,
             jalson::json_object(),
             args,
             [](XXX::wamp_call_result r)
             { rpc_call_cb(r);},
             (void*)"I_called_the_proc");
    wait_reply = true;
  }

  while ((long_wait || wait_reply) && ws->is_open())
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
        case eReplyReceived : wait_reply = false; break;
        case eClosed: break;
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


int main(int argc, char** argv)
{
  try {
    return main_impl(argc, argv);
  }
  catch (std::exception&e)
  {
    std::cout << "error, " << e.what() << std::endl;
    return 1;
  }
}

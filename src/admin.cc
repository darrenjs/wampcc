/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"
#include "wampcc/utils.h"

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
  enum class transport_bit
  {
    rawsocket = 0x01,
    websocket = 0x02,
  } transport = transport_bit::websocket;

  int serialisers = wampcc::all_serialisers;

  std::string username;
  std::string password;
  user_optional<std::string> realm;

  user_optional<std::string> addr;
  user_optional<std::string> port;

  std::list< std::string > subscribe_topics;

  std::string publish_topic;

  std::string call_procedure;

  int verbose = 0;
  bool no_uri_check = false;

  std::string arg_list;
  std::string arg_dict;

  std::chrono::seconds timeout { 3 };

  bool use_ssl = false;
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
  t_callback(wampcc::kernel* s, const char* d)
    : svc(s),
      request(d)
  {
  }
  wampcc::kernel* svc;
  const char* request;
};


void rpc_call_cb(wampcc::wamp_call_result r)
{
  if (r.was_error)
  {
    std::cout << "error: " << r.error_uri << ", list:"
              << r.args.args_list << ", dict:" << r.args.args_dict
              << std::endl;
  }
  else
  {

    std::cout << "result: list:"
              << r.args.args_list << ", dict:" << r.args.args_dict
              << std::endl;
  }
  std::lock_guard< std::mutex > guard( event_queue_mutex );
  event_queue.push( eReplyReceived );
  event_queue_condition.notify_one();
}

/* called upon subscribed and update events */
void subscribe_cb(wampcc::wamp_subscription_event ev)
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


#define HELPLN( X,S,T) std::cout << "  " << X << S << T << std::endl
static void usage()
{
  const char *sp2="\t\t";
  const char *sp3="\t\t\t";
  const char *sp4="\t\t\t\t";
  std::cout << "usage: admin [OPTIONS] ADDRESS PORT" << std::endl;
  std::cout << "Options:" << std::endl;
  HELPLN("-U, --username=ARG",sp2,"specify a session username");
  HELPLN("-P, --password=ARG",sp2,"specify a session password");
  HELPLN("-R, --realm=ARG",sp2,"specify a session realm");
  HELPLN("-s, --subscribe=URI",sp2,"subscribe to topic");
  HELPLN("-p, --publish=URI",sp2,"publish to topic");
  HELPLN("-c, --call=URI",sp2,"call procedure");
  HELPLN("--arglist=ARG",sp3,"wamp argument list, ARG is a JSON arra");
  HELPLN("--argdict=ARG",sp3,"wamp argument dictionary, ARG is a JSON object");
  HELPLN("--ssl", sp4, "connect using SSL/TLS socket");
  HELPLN("--timeout N", sp3, "wait upto N seconds during connect & logon");
  HELPLN("--proto PROTO_OPTIONS", sp2, "comma separated list of options, see below");
  HELPLN("-h", sp4, "display this help");
  HELPLN("-d [-d]", sp3, "verbose output, use -d -d for trace output");
  HELPLN("-v, --version", sp3, "print program version");
  std::cout << std::endl << "Protocol options:" <<std::endl
            << "  web - select websocket protocol" << std::endl
            << "  raw - select rawsocket protocol" << std::endl
            << "  json - support only json serialiser" << std::endl
            << "  msgpack - support only msgpack serialiser" << std::endl
            << "  ssl - use SSL/TLS transport" << std::endl;
  std::cout << std::endl << "Examples:" <<std::endl;
  std::cout << std::endl << "Call a procedure with JSON argument as array and object" << std::endl;
  std::cout << "  admin -U peter -P secret2 -R public -c set_color --arglist '[\"green\", \"light\"]'"   << std::endl;
  std::cout << "  admin -U peter -P secret2 -R public -c set_color --argdict '{\"foreground\" : \"red\"}'" << std::endl;

  exit(0);
}

void version()
{
  std::cout << wampcc::name_version()  << std::endl;
  exit(0);
}

void parse_proto(const char* src)
{
  auto keywords = wampcc::tokenize(src, ',', false);
  for (auto item : keywords)
  {
    if (item=="web")
      uopts.transport = user_options::transport_bit::websocket;
    else if (item=="raw")
      uopts.transport = user_options::transport_bit::rawsocket;
    else if (item=="ssl")
      uopts.use_ssl = true;
    else if (item=="json")
      uopts.serialisers = static_cast<int>(wampcc::serialiser_type::json);
    else if (item=="msgpack")
      uopts.serialisers = static_cast<int>(wampcc::serialiser_type::msgpack);
    else
      throw std::runtime_error("unknown proto flag");
  }
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
    OPT_NO_URI_CHECK = 1,
    OPT_ARGLIST,
    OPT_ARGDICT,
    OPT_SSL,
    OPT_TIMEOUT,
    OPT_PROTO,
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
    {"arglist",   required_argument, 0, OPT_ARGLIST},
    {"argdict",   required_argument, 0, OPT_ARGDICT},
    {"no-uri-check", no_argument,    0, OPT_NO_URI_CHECK},
    {"ssl",       no_argument,       0, OPT_SSL},
    {"timeout",   required_argument, 0, OPT_TIMEOUT},
    {"proto",     required_argument, 0, OPT_PROTO},
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
      case OPT_PROTO : parse_proto(optarg); break;
      case OPT_NO_URI_CHECK : uopts.no_uri_check = true; break;
      case OPT_ARGLIST : uopts.arg_list = optarg; break;
      case OPT_ARGDICT : uopts.arg_dict = optarg; break;
      case OPT_SSL : uopts.use_ssl = true; break;
      case OPT_TIMEOUT :
        uopts.timeout = std::chrono::seconds(atoi(optarg));
        break;
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
    wampcc::uri_regex uri_check;
    for (auto & i : uopts.subscribe_topics)
      if (not uri_check.is_strict_uri(i.c_str()))
        die("not strict uri: " + i);
  }
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


wampcc::config make_config()
{
  wampcc::config cfg;

  if (uopts.use_ssl)
    cfg.ssl.enable = true;

  return cfg;
}

int main_impl(int argc, char** argv)
{
  process_options(argc, argv);

  // take CALL parameters from command line
  wampcc::wamp_args args;
  if (!uopts.arg_list.empty())
  {
    try
    {
      wampcc::json_value jv = wampcc::json_decode(uopts.arg_list.c_str(), uopts.arg_list.size());
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
      auto jv = wampcc::json_decode(uopts.arg_dict.c_str(), uopts.arg_dict.size());
      if (!jv.is_object())
        throw std::runtime_error("expected JSON object");
      args.args_dict = jv.as_object();
    }
    catch (std::exception& e)
    {
      throw std::runtime_error(std::string("invalid argdict parameter, ") + e.what());
    }
  }

  /* Setup wampcc core components */

  int verbose = uopts.verbose;
  wampcc::logger console_logger {
    [verbose](wampcc::logger::Level l){
      switch (verbose) {
        case 2 : return l <= wampcc::logger::eTrace;
        case 1 : return l <= wampcc::logger::eInfo;
        default: return l <= wampcc::logger::eWarn;
      }
    },
    [verbose](wampcc::logger::Level, const std::string& msg, const char*, int){
      std::cout << msg << std::endl;
    }
  };

  std::unique_ptr<wampcc::kernel> g_kernel(
    new wampcc::kernel(make_config(), console_logger));

  wampcc::ssl_socket* sslsock = nullptr;
  std::unique_ptr<wampcc::tcp_socket> sock;
  if(uopts.use_ssl)
    sock.reset(sslsock = new wampcc::ssl_socket(g_kernel.get()));
  else
    sock.reset(new wampcc::tcp_socket(g_kernel.get()));

  std::future_status status;

  /* Make an attempt to connect to the target end point */
  auto fut = sock->connect(uopts.addr.value(), atoi(uopts.port.value().c_str()));

  /* Wait for a connection result */
  status = fut.wait_for(uopts.timeout);

  if (status == std::future_status::deferred)
    throw std::runtime_error("unexpected deffered connect");

  if (status == std::future_status::timeout)
    throw std::runtime_error("time-out during connect");

  if (status == std::future_status::ready)
  {
    wampcc::uverr ec = fut.get();
    if (ec)
      die("connect failed: " + std::to_string(ec.os_value()) + ", " + ec.message());
  }

  /* A result is available; our socket connection could be available. */

  if (!sock->is_connected())
    throw std::runtime_error("socket not connected");

  std::shared_ptr<wampcc::wamp_session> ws;

  switch (uopts.transport) {
    case user_options::transport_bit::websocket: {
      wampcc::websocket_protocol::options proto_opts;
      proto_opts.serialisers = uopts.serialisers;
      ws = wampcc::wamp_session::create<wampcc::websocket_protocol>(
        g_kernel.get(),
        std::move(sock),
        [](wampcc::session_handle wp, bool is_open) {
          if (auto sp = wp.lock())
            session_state_cb(is_open);
        }, proto_opts);
      break;
    }
    case user_options::transport_bit::rawsocket: {
      wampcc::rawsocket_protocol::options proto_opts;
      proto_opts.serialisers = uopts.serialisers;
      ws = wampcc::wamp_session::create<wampcc::rawsocket_protocol>(
        g_kernel.get(),
        std::move(sock),
        [](wampcc::session_handle wp, bool is_open) {
          if (auto sp = wp.lock())
            session_state_cb(is_open);
        }, proto_opts);
      break;
    }
  }

  if (!ws)
    throw std::runtime_error("failed to obtain wamp session");

  /* Perform an explicit SSL handshake.  This step is actually optional, since
   * the handshake will automatically be made during the wamp hello. */
  if (sslsock) {
    auto fut=sslsock->handshake();
    if (fut.wait_for(uopts.timeout)==std::future_status::timeout)
      throw std::runtime_error("time-out during ssl handshake");
    if (fut.get() != wampcc::ssl_socket::t_handshake_state::success)
      throw std::runtime_error("ssl handshake failed");
  }

  wampcc::client_credentials credentials;
  credentials.realm  = uopts.realm? uopts.realm.value() : "default_realm";
  credentials.authid = uopts.username;
  credentials.authmethods = {"wampcra"};
  credentials.secret_fn = [=]() -> std::string { return uopts.password; };

  ws->initiate_hello(credentials);

  /* Wait for the WAMP session to authenticate and become open */
  {
    std::unique_lock<std::mutex> guard(g_active_session_mutex);

    bool hasevent = g_active_session_condition.wait_for(guard,
                                                        uopts.timeout,
                                                        [](){ return g_active_session_notifed; });

    if (!hasevent)
      throw std::runtime_error("timeout when establishing wamp session");
  }

  if (!g_handshake_success)
    throw std::runtime_error("wamp session could not be established");

  /* WAMP session is now open  */

  bool long_wait = false;
  bool wait_reply = false;

  // wampcc::basic_list my_list;
  // wampcc::basic_list::list_events obs;
  // auto displayer = [&my_list]()
  //   {
  //     json_array value = my_list.copy_value();
  //     std::cout << "list: ";
  //     for (auto & item : value)
  //       std::cout << item << ",";
  //     std::cout << std::endl;
  //   };
  // obs.on_insert = [&my_list, displayer](size_t, const json_value&) {displayer();};
  // obs.on_replace = [&my_list, displayer](size_t, const json_value&) {displayer();};
  // obs.on_erase = [&my_list, displayer](size_t) {displayer();};
  // obs.on_reset = [&my_list, displayer](const wampcc::basic_list::internal_impl&) {displayer();};
  // my_list.add_observer(obs);



  // subscribe to user topics
  wampcc::subscribed_cb scb; // TODO:
  wampcc::json_object sub_options { {KEY_PATCH, 1} };
  if (! uopts.subscribe_topics.empty()) long_wait = true;
  for (auto & topic : uopts.subscribe_topics)
    ws->subscribe(topic, sub_options, scb, subscribe_cb, nullptr);


  // publish
  if (!uopts.publish_topic.empty())
  {
    ws->publish(uopts.publish_topic,
                wampcc::json_object(),
                args);

    // wampcc::basic_text_model tm;
    // wampcc::topic publisher(uopts.publish_topic, &tm);
    // publisher.add_wamp_session(ws);

    // tm.set_value("hello world");
  }

  // call a remote procedure
  if (!uopts.call_procedure.empty())
  {
    ws->call(uopts.call_procedure,
             wampcc::json_object(),
             args,
             [](wampcc::wamp_call_result r)
             { rpc_call_cb(r);});
    wait_reply = true;
  }

  while ((long_wait || wait_reply) && ws->is_open())
  {
    std::unique_lock< std::mutex > guard( event_queue_mutex );

    /*bool hasevent =*/ event_queue_condition.wait_for(guard, uopts.timeout,
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

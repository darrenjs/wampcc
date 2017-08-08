/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"
#include "wampcc/utils.h"

#include <algorithm>
#include <sstream>

#include <getopt.h> /* for getopt_long; standard getopt is in unistd.h */

#define LOG(X)                                                                 \
  do {                                                                         \
    auto level = wampcc::logger::eInfo;                                        \
    if (logger.wants_level && logger.write && logger.wants_level(level)) {     \
      std::ostringstream __xx_oss;                                             \
      __xx_oss << X;                                                           \
      logger.write(level, __xx_oss.str(), __FILE__, __LINE__);                 \
    }                                                                          \
  } while (0)


const std::string uri_double = "double";

enum class role { invalid = 0, router, callee, caller, publisher, subscriber };

wampcc::wamp_args const final_item {{"final"},{{"final",1}}};

struct user_options
{
  enum class transport {
    rawsocket,
    websocket,
  } session_transport = transport::websocket;

  int serialisers = wampcc::all_serialisers;

  wampcc::user_optional<std::string> admin_port;
  wampcc::user_optional<std::string> port;
  wampcc::user_optional<int> count;
  role program_role = role::invalid;
  std::string realm = "default_realm";
  bool debug = false;
  bool use_websocket = false;
  bool use_ssl = false;
} uopts;

wampcc::logger logger;

class tester
{
private:
  std::unique_ptr<wampcc::kernel> m_kernel;
  std::shared_ptr<wampcc::wamp_router> m_router;
  std::shared_ptr<wampcc::wamp_router> m_admin;
  std::shared_ptr<wampcc::wamp_session> m_callee;
  std::shared_ptr<wampcc::wamp_session> m_subscriber;
  std::vector<wampcc::wamp_args> m_subscription_data;

public:
  // control when main thread can exit
  std::promise<int> can_exit;

  void create_kernel()
  {
    auto loglevel =
        uopts.debug ? wampcc::logger::eDebug : wampcc::logger::eInfo;
    logger = wampcc::logger::stream(wampcc::logger::lockable_cout,
                                    wampcc::logger::levels_upto(loglevel));
    m_kernel.reset(new wampcc::kernel({}, logger));
  }

  void create_router()
  {
    m_router.reset(new wampcc::wamp_router(m_kernel.get()));
    logger.write(wampcc::logger::eInfo,
                 "router listening on " + uopts.port.value(), __FILE__,
                 __LINE__);
    m_router->listen(wampcc::auth_provider::no_auth_required(),
                     std::atoi(uopts.port.value().c_str()));
  }

  std::shared_ptr<wampcc::wamp_session> connect_and_logon()
  {
    std::string host = "127.0.0.1";

    std::unique_ptr<wampcc::tcp_socket> sock(
        new wampcc::tcp_socket(m_kernel.get()));
    auto fut = sock->connect(host, uopts.port.value());

    if (fut.wait_for(std::chrono::milliseconds(250)) !=
        std::future_status::ready)
      throw std::runtime_error("timeout during connect");

    if (auto ec = fut.get())
      throw std::runtime_error("connect failed: " +
                               std::to_string(ec.os_value()) + ", " +
                               ec.message());

    auto on_session_state = [this](wampcc::wamp_session&, bool is_open) {
      if (!is_open)
        try {
          this->can_exit.set_value(0);
        } catch (...) { /* ignore promise already set error */
        }
    };
    std::shared_ptr<wampcc::wamp_session> session;

    switch (uopts.session_transport) {
      case user_options::transport::websocket: {
        wampcc::websocket_protocol::options proto_opts;
        proto_opts.serialisers = uopts.serialisers;
        session = wampcc::wamp_session::create<wampcc::websocket_protocol>(
            m_kernel.get(), std::move(sock), on_session_state, proto_opts);
        break;
      }
      case user_options::transport::rawsocket: {
        wampcc::rawsocket_protocol::options proto_opts;
        proto_opts.serialisers = uopts.serialisers;
        session = wampcc::wamp_session::create<wampcc::rawsocket_protocol>(
            m_kernel.get(), std::move(sock), on_session_state, proto_opts);
        break;
      }
    }

    wampcc::client_credentials credentials;
    credentials.realm = uopts.realm;
    auto logon_fut = session->hello(credentials);

    if (logon_fut.wait_for(std::chrono::seconds(5)) !=
        std::future_status::ready)
      throw std::runtime_error("time-out during wamp session logon");

    if (!session->is_open())
      throw std::runtime_error("wamp session logon failed");

    return session;
  }

  void create_callee()
  {
    std::shared_ptr<wampcc::wamp_session> session = connect_and_logon();

    wampcc::json_object options;

    std::promise<std::tuple<bool, std::string>> promise;

    auto on_result = [&](wampcc::wamp_session&, wampcc::registered_info info) {
      bool is_good = !info.was_error;
      std::string error_uri = info.error_uri;
      std::tuple<bool, std::string> result{is_good, error_uri};
      promise.set_value(result);
    };

    auto on_invoke = [](wampcc::wamp_session& ws,
                        wampcc::invocation_info invoc) {
      for (auto& item : invoc.args.args_list)
        if (item.is_string())
          item = item.as_string() + item.as_string();

      ws.yield(invoc.request_id, std::move(invoc.args.args_list));
    };

    session->provide(uri_double, options, std::move(on_result),
                     std::move(on_invoke));

    auto fut = promise.get_future();
    if (fut.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
      throw std::runtime_error("timeout during rpc registration");

    auto result = fut.get();
    if (std::get<0>(result) == false)
      throw std::runtime_error("rpc registration failed: " +
                               std::get<1>(result));

    m_callee = std::move(session);
  }

  void create_caller()
  {
    if (!uopts.count)
      throw std::runtime_error("missing count");

    std::shared_ptr<wampcc::wamp_session> session = connect_and_logon();

    for (int i = 0; i < uopts.count.value(); i++) {
      std::promise<wampcc::result_info> promised_result;

      wampcc::wamp_args call_args;
      call_args.args_list = {"hello", "world", std::to_string(i)};

      session->call(uri_double, {}, call_args, [&](wampcc::wamp_session&, wampcc::result_info r) {
          try {
            promised_result.set_value(r);
          } catch (...) { /* ignore promise already set error */ }
        });


      auto fut = promised_result.get_future();
      if (fut.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
        throw std::runtime_error("timeout during call");

      auto result = fut.get();
      if (result.was_error)
        throw std::runtime_error("call error: " + result.error_uri);

      // expected value
      for (auto& item : call_args.args_list)
        if (item.is_string())
          item = item.as_string() + item.as_string();

      if (call_args != result.args)
        throw std::runtime_error("rpc result did not match expected");
    }

    LOG("rpc result successful, closing session");

    if (session->close().wait_for(std::chrono::seconds(1))
        != std::future_status::ready)
      throw std::runtime_error("timeout during session close");
  }

  void create_admin_port()
  {
    m_admin.reset(new wampcc::wamp_router(m_kernel.get()));
    logger.write(wampcc::logger::eInfo,
                 "admin listening on " + uopts.admin_port.value(), __FILE__,
                 __LINE__);
    std::future<wampcc::uverr> futerr =
      m_admin->listen(wampcc::auth_provider::no_auth_required(),
                      std::atoi(uopts.admin_port.value().c_str()));

    if (futerr.wait_for(std::chrono::milliseconds(250)) !=
        std::future_status::ready)
      throw std::runtime_error("timeout during listen(admin)");

    if (auto ec = futerr.get())
      throw std::runtime_error("listen failed: " +
                               std::to_string(ec.os_value()) + ", " +
                               ec.message());

    m_admin->callable("default_realm", "stop",
                      [this](wampcc::wamp_router&, wampcc::wamp_session&, wampcc::call_info) {
                        this->can_exit.set_value(0);
                      });
  }


  std::vector<wampcc::wamp_args> data_set() const
  {
    std::vector<wampcc::wamp_args> retval;
    retval.reserve(uopts.count.value()+1);

    for (int i = 0; i < uopts.count.value(); i++) {
      wampcc::wamp_args args;
      args.args_list.push_back(wampcc::json_value::make_uint(i));
      retval.push_back(std::move(args));
    }
    retval.push_back(final_item);
    return retval;
  }

  void create_publisher()
  {
    if (!uopts.count)
      throw std::runtime_error("missing count");

    {
      std::shared_ptr<wampcc::wamp_session> session = connect_and_logon();

      std::string uri_numbers_topic = "numbers";

      auto data_to_send = data_set();
      for (auto& item : data_to_send)
        session->publish(uri_numbers_topic, {}, std::move(item));
    }
    can_exit.set_value(0);
  }

  void create_subscriber()
  {
    if (!uopts.count)
      throw std::runtime_error("missing count");

    auto data_execpt = data_set();
    decltype(data_execpt) data_actual;

    std::shared_ptr<wampcc::wamp_session> session = connect_and_logon();

    std::promise<wampcc::subscribed_info> promised_result;

    auto on_subscribed = [&](wampcc::wamp_session&, wampcc::subscribed_info& r) {
      promised_result.set_value(std::move(r));
    };
    auto on_event = [this](wampcc::wamp_session&, wampcc::event_info info) {
      LOG("subscription event: " << info.args.args_list);
      bool is_final = info.args == final_item;
      m_subscription_data.push_back(std::move(info.args));

      if (is_final) {
        auto expect = data_set();
        if (m_subscription_data == expect) {
          LOG("received expected data set");
          can_exit.set_value(0);
        }
        else {
          LOG("received unexpected data set");
          can_exit.set_value(1);
        }

      }

    };

    std::string uri_numbers_topic = "numbers";
    wampcc::json_object options;
    wampcc::wamp_args args;

    session->subscribe(uri_numbers_topic, options, on_subscribed, on_event);

    auto fut = promised_result.get_future();
    if (fut.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
      throw std::runtime_error("timeout during subscribe");

    auto subscribed_result = fut.get();
    if (subscribed_result.was_error)
      throw std::runtime_error("subscribe error: " +
                               subscribed_result.error_uri);

    m_subscriber = std::move(session);
  }
};

void parse_proto(const char* src)
{
  for (auto str : wampcc::tokenize(src, ',', false)) {
    if (str == "web")
      uopts.session_transport = user_options::transport::websocket;
    else if (str == "raw")
      uopts.session_transport = user_options::transport::rawsocket;
    else if (str == "ssl")
      uopts.use_ssl = true;
    else if (str == "json")
      uopts.serialisers = static_cast<int>(wampcc::serialiser_type::json);
    else if (str == "msgpack")
      uopts.serialisers = static_cast<int>(wampcc::serialiser_type::msgpack);
    else
      throw std::runtime_error("unknown proto flag");
  }
}

#define HELPLN(X, S, T) std::cout << "  " << X << S << T << std::endl
void usage()
{
  const char* sp1 = "\t";
  const char* sp2 = "\t\t";

  std::cout << "usage: wampcc_tester [OPTIONS]" << std::endl;
  std::cout << "Options:" << std::endl;
  HELPLN("--router", sp2, "router role");
  HELPLN("--caller", sp2, "caller role");
  HELPLN("--callee", sp2, "callee role");
  HELPLN("--subscriber", sp2, "subscriber role");
  HELPLN("--publisher", sp2, "publisher role");
  HELPLN("-a, --admin_port=ARG", sp1, "specify admin port");
  HELPLN("-p, --port", sp2, "wamp connection port");
  HELPLN("-d, --debug", sp2, "increased logging");
  HELPLN("-c, --count=N", sp2, "number of messages to-send / expect-receive");
  HELPLN("--proto PROTO_OPTS", sp1,
         "comma separated list of options, default 'web,json'");
  std::cout << std::endl << "Protocol options:" << std::endl
            << "  web - select websocket protocol" << std::endl
            << "  raw - select rawsocket protocol" << std::endl
            << "  json - support only json serialiser" << std::endl
            << "  msgpack - support only msgpack serialiser" << std::endl;
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
  enum {
    OPT_NO_URI_CHECK = 1,
    OPT_ARGLIST,
    OPT_ARGDICT,
    OPT_TIMEOUT,
    OPT_PROTO,
    OPT_ROUTER,
    OPT_CALLEE,
    OPT_CALLER,
    OPT_PUBLISHER,
    OPT_SUBSCRIBER
  };

  //  int digit_optind = 0;
  static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"router", no_argument, 0, OPT_ROUTER},
      {"callee", no_argument, 0, OPT_CALLEE},
      {"caller", no_argument, 0, OPT_CALLER},
      {"publisher", no_argument, 0, OPT_PUBLISHER},
      {"subscriber", no_argument, 0, OPT_SUBSCRIBER},
      {"proto", required_argument, 0, OPT_PROTO},
      {"admin_port", required_argument, 0, 'a'},
      {"port", required_argument, 0, 'p'},
      {"debug", no_argument, 0, 'd'},
      {"count", required_argument, 0, 'c'},
      {NULL, 0, NULL, 0}};
  const char* optstr = "hp:a:dc:"; // short opt string

  ::opterr = 1;

  while (true) {
    /* "optind" is the index of the next element to be processed in argv.  It
       is defined in the getopts header, and the system initializes this value
       to 1.  The caller can reset it to 1 to restart scanning of the same
       argv, or when scanning a new argument vector. */

    // take a copy to remember value for after return from getopt_long()
    // int this_option_optind = ::optind ? ::optind : 1;
    int long_index = 0;

    int c = getopt_long(argc, argv, optstr, long_options, &long_index);
    if (c == -1)
      break;

    switch (c) {
      case OPT_PROTO:
        parse_proto(optarg);
        break;
      case OPT_ROUTER:
        uopts.program_role = role::router;
        break;
      case OPT_CALLER:
        uopts.program_role = role::caller;
        break;
      case OPT_PUBLISHER:
        uopts.program_role = role::publisher;
        break;
      case OPT_SUBSCRIBER:
        uopts.program_role = role::subscriber;
        break;
      case OPT_CALLEE:
        uopts.program_role = role::callee;
        break;
      case 'a':
        uopts.admin_port = optarg;
        break;
      case 'p':
        uopts.port = optarg;
        break;
      case 'd':
        uopts.debug = true;
        break;
      case 'h':
        usage();
        break;
      case 'c':
        uopts.count = std::atoi(optarg);
        break;
      case '?':
        exit(1); // invalid option
      default: {
        std::cout << "unknown option: -" << char(c) << "\n";
        exit(1);
      }
    }
  } // while

  if (uopts.program_role == role::invalid)
    throw std::runtime_error("missing role");

  if (!uopts.port)
    throw std::runtime_error("missing port");
}


int main_impl(int argc, char** argv)
{
  process_options(argc, argv);

  tester impl;

  impl.create_kernel();

  if (uopts.admin_port)
    impl.create_admin_port();

  switch (uopts.program_role) {
    case role::invalid:
      throw std::runtime_error("role not specified");
      break;
    case role::router:
      impl.create_router();
      break;
    case role::callee:
      impl.create_callee();
      break;
    case role::caller:
      impl.create_caller();
      break;
    case role::publisher:
      impl.create_publisher();
      break;
    case role::subscriber:
      impl.create_subscriber();
      break;
  }

  /* Suspend main thread */

  int result = impl.can_exit.get_future().get();

  return result;
}


int main(int argc, char** argv)
{
  try {
    return main_impl(argc, argv);
  } catch (std::exception& e) {
    std::cout << "error, " << e.what() << std::endl;
    return 1;
  }
}

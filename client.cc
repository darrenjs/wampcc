

#include <Topic.h>
#include <dealer_service.h>
#include <Logger.h>
#include <kernel.h>

#include <condition_variable>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include <unistd.h>
#include <string.h>
#include <sys/time.h>

XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eInfo,
                                              true);

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

XXX::text_topic topic("topic1");

void procedure_error_cb(XXX::invoke_details& invocation)
{
  const callback_t* cbdata = (callback_t*) invocation.user;

  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< invocation.uri << "' invoked, args: " << invocation.args.args_list
          << ", user:" << cbdata->request );

  throw XXX::invocation_exception("opps, cannot fulfill RPC");

}

void procedure_cb(XXX::invoke_details& invocation)
{
  const callback_t* cbdata = (callback_t*) invocation.user;

  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< invocation.uri << "' invoked, args: " << invocation.args.args_list
          << ", user:" << cbdata->request );

//  throw std::runtime_error("bad alloc");
  auto my_args = invocation.args;

  my_args.args_list = jalson::json_array();
  jalson::json_array & arr = my_args.args_list.as_array();
  arr.push_back("hello");
  arr.push_back("back");

  invocation.yield_fn(my_args);
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

XXX::dealer_service * g_dealer = nullptr;

void publisher_tep()
{
  while(true)
  {
    usleep(1000000*5);
    std::string newvalue = "0000____" + get_timestamp();
    topic.update( newvalue.c_str() ); // Legacy ... currently not functional

    XXX::wamp_args wargs;
    wargs.args_list = jalson::json_value::make_array();
    wargs.args_list.as_array().push_back( newvalue );

    if (g_dealer) g_dealer->publish("USERHB",
                                    "default_realm",
                                    jalson::json_object(),
                                    wargs);
  }

}



int main(int /* argc */, char** /* argv */)
{
  std::unique_ptr<XXX::kernel> mycs ( new XXX::kernel(logger) );

  XXX::dealer_service * dealer = new XXX::dealer_service(*(mycs.get()), nullptr);
  g_dealer = dealer;
  dealer->listen(55555);

  // std::unique_ptr<callback_t> cb1( new callback_t(mycs.get(),"my_hello") );
  // std::unique_ptr<callback_t> cb2( new callback_t(mycs.get(),"my_start") );
  // std::unique_ptr<callback_t> cb3( new callback_t(mycs.get(),"my_stop") );

  // mycs->add_procedure("hello", jalson::json_object(), procedure_cb, (void*) cb1.get());
  // mycs->add_procedure("start", jalson::json_object(), procedure_cb, (void*) cb2.get());
  // mycs->add_procedure("stop",  jalson::json_object(), procedure_cb, (void*) cb3.get());

  // mycs->add_topic( &topic );

  mycs->start();

  std::thread publisher( publisher_tep );

  //XXX::dealer_service* dealer = mycs->get_dealer();

  std::unique_ptr<callback_t> cb1( new callback_t(mycs.get(),"my_run") );
  std::unique_ptr<callback_t> cb2( new callback_t(mycs.get(),"my_error") );

  dealer->register_procedure("default_realm",
                             "run",
                             jalson::json_object(),
                             procedure_cb, (void*) cb1.get());

  dealer->register_procedure("default_realm",
                             "erun",
                             jalson::json_object(),
                             procedure_error_cb, (void*) cb2.get());

  while(1) sleep(10);

  // explicit deletion for better control

  publisher.join();
  mycs.reset();
  delete logger;
  return 0;
}

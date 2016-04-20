

#include <Topic.h>
#include <client_service.h>
#include <Logger.h>

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
  callback_t(XXX::client_service* s, const char* d)
    : svc(s),
      request(d)
  {
  }
  XXX::client_service* svc;
  const char* request;
};

XXX::text_topic topic("topic1");

void procedure_cb(XXX::t_invoke_id invokeid,
                  const std::string& procedure,
                  XXX::rpc_args& the_args,
                  XXX::session_handle&,
                  void*  user  )
{
  const callback_t* cbdata = (callback_t*) user;

  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< procedure << "' invoked, args: " << the_args.args
          << ", user:" << cbdata->request );

//  throw std::runtime_error("bad alloc");
  auto my_args = the_args;

  my_args.args = jalson::json_array();
  jalson::json_array & arr = my_args.args.as_array();
  arr.push_back("hello");
  arr.push_back("back");
  cbdata->svc->post_reply(invokeid, my_args);



/*
  // TODO: I have commented out this message, because presently I dont have a way to signify, on the first message, that there are more replies to come!
  std::string uri = "mine.error.system_not_ready";
  clsvc.post_error(src, req_id, uri);
*/


  /* TODO: how do I respond with an ERROR or a RESULT?

     - need to make a call back into client service
     -> can happen during call, or later on any other thread


     - probably need to cache the ID's, inside the client_service? ie, have some
     kind of state to rememeber the callback is being made?

     - do we need to go via the EVL ? might be easier to do that initially.
     Also see if I can unify the approaches taken for YIELD and ERROR and
     REGISTERED.

  */

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

void publisher_tep()
{
  while(true)
  {
    usleep(250);
    std::string newvalue = "0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____0000____new@" + get_timestamp();
    topic.update( newvalue.c_str() );
  }
}



int main(int /* argc */, char** /* argv */)
{
  XXX::client_service::config cfg;
  cfg.server_port = 55555;
  cfg.enable_embed_router = true;

  std::unique_ptr<XXX::client_service> mycs ( new XXX::client_service(logger, cfg) );

  std::unique_ptr<callback_t> cb1( new callback_t(mycs.get(),"my_hello") );
  std::unique_ptr<callback_t> cb2( new callback_t(mycs.get(),"my_start") );
  std::unique_ptr<callback_t> cb3( new callback_t(mycs.get(),"my_stop") );

  mycs->add_procedure("hello", procedure_cb, (void*) cb1.get());
  mycs->add_procedure("start", procedure_cb, (void*) cb2.get());
  mycs->add_procedure("stop",  procedure_cb, (void*) cb3.get());

  mycs->add_topic( &topic );

  mycs->start();

  std::thread publisher( publisher_tep );

  while(1) sleep(10);

  // explicit deletion for better control

  publisher.join();
  mycs.reset();
  delete logger;
  return 0;
}

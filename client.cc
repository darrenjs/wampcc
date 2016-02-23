

#include <Topic.h>
#include <Table.h>
#include <client_service.h>
#include <Logger.h>

#include <sstream>
#include <condition_variable>
#include <mutex>
#include <iostream>

#include <unistd.h>
#include <string.h>

XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                              XXX::Logger::eInfo,
                                              true);


void procedure_cb(XXX::client_service& clsvc,
                  XXX::t_sid sid,
                  const std::string& procedure,
                  XXX::t_request_id req_id,
                  XXX::rpc_args& the_args,
                  void*  user  )
{
  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< procedure << "' invoked, args: " << the_args.args
          << ", user:" << (const char*) user
          << ", req_id:" << req_id);

  auto my_args = the_args;

  my_args.args = jalson::json_array();
  jalson::json_array & arr = my_args.args.as_array();
  arr.push_back("hello");
  arr.push_back("back");
  clsvc.post_reply(sid, req_id, my_args);


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



int main(int /* argc */, char** /* argv */)
{

  /* TODO: review the jalson bug.  If I do this type:

     jalson::json_value * ptr;
     jalson::json_value copy ( ptr);

     ... it create a 'true' value. Not what the user would expect.  I
     encountered it specifically on the function call.
  */


  /* new client service */

  XXX::client_service::config cfg;
  cfg.port = 55555;
  XXX::client_service mycs( logger, cfg);

  mycs.add_procedure("hello", procedure_cb, (void*)"my_hello");
  mycs.add_procedure("start", procedure_cb, (void*)"my_start");
  mycs.add_procedure("stop",  procedure_cb, (void*)"my_stop");

  mycs.start();

  while (1)  sleep(15);

  std::cout << "exiting\n";
  return 0;
}

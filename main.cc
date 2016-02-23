

#include <NexioServer.h>
#include "Topic.h"
#include "Table.h"
#include "Session.h"
#include "Logger.h"

#include "event_loop.h"
#include "client_service.h"
#include "dealer_service.h"

#include <Logger.h>

#include <sstream>
#include <condition_variable>
#include <mutex>
#include <iostream>

#include <unistd.h>
#include <string.h>

XXX::NexioServer * server = nullptr;

  XXX::Logger * logger = new XXX::ConsoleLogger(XXX::ConsoleLogger::eStdout,
                                                XXX::Logger::eAll,
                                                true);


void procedure_cb(XXX::client_service& /*clsvc*/,
                  XXX::SID /*src*/,
                  const std::string& procedure,
                  XXX::t_request_id /*req_id*/,
                  XXX::rpc_args& the_args,
                  void* /* user */ )
{
  /* called when a procedure within a CALLEE is triggered */
  auto __logptr = logger;
  _INFO_ ("CALLEE has procuedure '"<< procedure << "' invoked, args: " << the_args.args);

  auto my_args = the_args;

  my_args.args = jalson::json_array();
  jalson::json_array & arr = my_args.args.as_array();
  arr.push_back("hello");
  arr.push_back("back");
//  clsvc.post_reply(src, req_id, my_args);

  std::string uri = "mine.error.system_not_ready";
  // clsvc.post_error(src, req_id, uri);

  /* TODO: how do I respond with an ERROR or a RESULT?

     - need to make a call back into client service
       -> can happen during call, or later on any other thread

     - need the destination SID, so that if our client_service does have
       multiple sessions, then we ensure it gets routed correctly

     - need to transmit data

     - probably need to cache the ID's, inside the client_service? ie, have some
       kind of state to rememeber the callback is being made?

     - do we need to go via the EVL ? might be easier to do that initially.
       Also see if I can unify the approaches taken for YIELD and ERROR and
       REGISTERED.

   */

  // TODO: how to I ensure the user arguments are transmitted?



}


void call_cb(XXX::call_info& info, XXX::rpc_args& args, void* cb_user_data)
{
  auto __logptr = logger;
  const char* msg = ( const char* ) cb_user_data;

  _INFO_( "CALLER received reply in main, args="
          << args.args << ", cb_user_data: " << msg
          << ", reqid: " << info.reqid
          << ", proc:" << info.procedure );
}

int tep()
{
  auto __logptr = logger;
  _INFO_( "tep started" );

  sleep(3);



  XXX::Topic * topic = new XXX::Topic("T1");
  server -> addTopic( topic );

  XXX::Table * topictable = new XXX::Table("T2");
  server -> addTopic( topictable );

  std::vector<std::string> cols = {"health","status","post"};
  topictable->add_columns( cols );


  int rowid = 2;
  while (1)
  {
    sleep(1);

    rowid++;
    std::ostringstream os;
    os << "R_"  << rowid;

    topictable->update_row("r1", "f1", "v1");
    topictable->update_row(os.str(), "f1", "v1");
  }
  return 0;
}


std::mutex              g_active_session_mutex;
std::condition_variable g_active_session_condition;
XXX::Session* active_session = nullptr;
bool g_active_session_notifed = false;

void connect_cb(XXX::Session* session, int status)
{
  auto __logptr = logger;
  std::lock_guard<std::mutex> guard(g_active_session_mutex);
  active_session = session;
  g_active_session_notifed = true;
  _INFO_( "got session, status=" << status );
  g_active_session_condition.notify_one();
}


int main()
{

//   if (strcmp(argv[1],"-d")==0)
//   {
//     /* new client service */

//     XXX::dealer_service d( logger );

//     // start the internal thread of the client
//     std::cout << "starting\n";
//     d.start();

//     // sleep until main loop is ready
//     sleep(1);

//     std::cout << "makeing connect attempt\n";
//     XXX::dealer_service::Request req;
//     req.addr = "127.0.0.1";
//     req.port = 55555;
//     req.cb   = connect_cb;
//     d.connect( req );

//     // wait for a connection attempt to complete
//     {
//       std::unique_lock<std::mutex> locker(g_active_session_mutex);
//       while( !g_active_session_notifed )
//       {
//         g_active_session_condition.wait( locker );  // TODO: put in a time limit?
//       }
//     }

//     sleep(5);
// //    active_session->call( "stop" ); // NO: should not be sending a call! we are connected as a dealer!
//     XXX::rpc_args args;
//     jalson::json_array ja;
//     ja.push_back( "hello" );
//     ja.push_back( "world" );   //TODO: why do I not see thi value arrise at the other side? Jalson error?
//     args.args = ja ;


//     std::string encoding = jalson::encode( args.args );

//     args.args = jalson::json_value::make_null();
//     d.call_rpc("stop",
//                [](XXX::call_info& reqdet, XXX::rpc_args& args, void* cb_data){call_cb(reqdet, args, cb_data);},
//                args, (void*)"I_called_stop");


//     sleep(5);
// //    active_session->call( "stop" ); // NO: should not be sending a call! we are connected as a dealer!

//     d.call_rpc("start", [](XXX::call_info& reqdet, XXX::rpc_args& args, void * cb_data){ call_cb(reqdet, args, cb_data);}, XXX::rpc_args(),
//                (void*)"I_called_start");


//     while(1) { sleep(100); }
//   }


  /* TODO: review the jalson bug.  If I do this type:

     jalson::json_value * ptr;
     jalson::json_value copy ( ptr);

     ... it create a 'true' value. Not what the user would expect.  I
     encountered it specifically on the function call.
   */


  while (1)
  {
    sleep(10);
  }


  return 0;
}

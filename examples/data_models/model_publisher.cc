

#include "XXX/wamp_router.h"
#include "XXX/kernel.h"
#include "XXX/data_model.h"

#include <condition_variable>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <random>

#include <unistd.h>
#include <string.h>
#include <sys/time.h>

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


class planets_list
{
public:

  planets_list();
  ~planets_list();

  void thread_main();

  XXX::list_model model;

private:

  std::promise<void> m_notify_to_exit;
  std::thread m_thread; /* keep as final member, to avoid race condition */
};



planets_list::planets_list()
  : m_thread( &planets_list::thread_main, this )
{
}


planets_list::~planets_list()
{
  m_notify_to_exit.set_value();
  m_thread.join();
}


void planets_list::thread_main()
{
  auto exit_fut = m_notify_to_exit.get_future();
  auto delay = std::chrono::milliseconds(2000);

  const char* const names[] = { "sun", "mercury", "venus", "earth", "mars", "jupiter", "saturn", "uranus", "neptune", "pluto"};

  std::random_device rd;
  int seed = 0;
  std::mt19937 gen( seed );
  std::uniform_int_distribution<> dis(0, 9);
  while(true)
  {
    if (exit_fut.wait_for(delay) == std::future_status::ready)
      return;

    std::string newvalue = "0000____" + get_timestamp();


    XXX::wamp_args wargs;
    wargs.args_list.push_back( newvalue );

    // if (g_dealer) g_dealer->publish("USERHB",
    //                                 "default_realm",
    //                                 jalson::json_object(),
    //                                 wargs);

    //text_data.set_value(newvalue);

    //std::cout << "PRIOR:" << model.value() << "\n";
    switch ( dis(gen) % 7 )
    {
      case 0 : model.insert(0, names[dis(gen)]); break;
      case 1 : if (model.value().size()>0 && model.value().size()<10) model.insert(model.value().size()-1, names[dis(gen)]); break;
      case 2 : if (model.value().size()>0)  model.replace(0, names[dis(gen)]); break;
      case 3 : if (model.value().size()>0)  model.replace(model.value().size()-1, names[dis(gen)]); break;
      case 4 : if (model.value().size()>0)  model.erase(0); break;
      case 5 : if (model.value().size()>0)  model.erase(model.value().size()-1); break;
      default: if (model.value().size()<10) model.push_back( names[dis(gen)] );
    };
    //std::cout << "ACTUAL:" << model.value() << "\n";
  }

}




planets_list planets;
XXX::model_topic & topic =  planets.model.get_topic("planets");




std::shared_ptr<XXX::wamp_router> g_dealer;

int main(int /* argc */, char** /* argv */)
{
  auto __logger = XXX::logger::stdlog(std::cout,
                                      XXX::logger::levels_all(),
                                      true);

  std::unique_ptr<XXX::kernel> the_kernel(new XXX::kernel({},__logger));

  std::shared_ptr<XXX::wamp_router> dealer ( new XXX::wamp_router(the_kernel.get(), nullptr) );
  g_dealer = dealer;

  std::string realm = "default_realm";
  topic.add_publisher(realm, g_dealer);

  XXX::auth_provider server_auth;
  server_auth.provider_name = [](const std::string){ return "programdb"; };
  server_auth.permit_user_realm = [](const std::string& /*user*/,
                                     const std::string& /*realm*/){
    return XXX::auth_provider::auth_plan(XXX::auth_provider::e_open, {});
  };
  server_auth.get_user_secret   = [](const std::string& /*user*/, const std::string& /*realm*/){ return "";};

  // start listening for sessions
  int port = 44444;
  std::cout << "listening on port " << port << std::endl;
  std::future<XXX::uverr> fut_listen_err = dealer->listen(port, server_auth);
  std::future_status status = fut_listen_err.wait_for(std::chrono::seconds(2));

  if (status == std::future_status::ready)
  {
    XXX::uverr err = fut_listen_err.get();
    if (err)
    {
      std::cout << "listen failed, " << err <<  "\n";
      return err.os_value();
    }
  }
  else
  {
    std::cout << "timeout waiting for listen socket\n";
    return 1;
  }


  while(1) sleep(10);

  // explicit deletion for better control

  the_kernel.reset();

  return 0;
}

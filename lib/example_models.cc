#include "XXX/example_models.h"

#include <iostream>

#include <unistd.h>
#include <sys/time.h>

static std::string get_timestamp()
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

namespace XXX {

planets_list::planets_list()
  : m_thr( &planets_list::thread_main, this )
{
}


planets_list::~planets_list()
{
  m_notify_to_exit.set_value();
  m_thr.join();
}


void planets_list::thread_main()
{
  auto exit_fut = m_notify_to_exit.get_future();
  auto delay = std::chrono::milliseconds(10000);

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


    //std::cout << "PRIOR:" << model.copy_value() << "\n";
    switch ( dis(gen) % 7 )
    {
      case 0 : model.insert(0, names[dis(gen)]); break;
      case 1 : if (model.copy_value().size()>0 && model.copy_value().size()<10) model.insert(model.copy_value().size()-1, names[dis(gen)]); break;
      case 2 : if (model.copy_value().size()>0) model.replace(0, names[dis(gen)]); break;
      case 3 : if (model.copy_value().size()>0) model.replace(model.copy_value().size()-1, names[dis(gen)]); break;
      case 4 : if (model.copy_value().size()>0) model.erase(0); break;
      case 5 : if (model.copy_value().size()>0) model.erase(model.copy_value().size()-1); break;
      default: if (model.copy_value().size()<10) model.push_back( names[dis(gen)] );
    };
    //std::cout << "ACTUAL:" << model.copy_value() << "\n";

  }

}


}

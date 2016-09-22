#ifndef XXX_EXAMPLE_MODELS_H
#define XXX_EXAMPLE_MODELS_H

#include "topic.h"

namespace XXX {


class planets_list
{
public:

  planets_list();
  ~planets_list();

  void thread_main();

  basic_list model;

private:

  std::thread m_thr;
  std::promise<void> m_notify_to_exit;
};

}


#endif

#ifndef XXX_EXAMPLE_MODELS_H
#define XXX_EXAMPLE_MODELS_H

#include "XXX/topic.h"

namespace XXX {


class planets_list
{
public:

  planets_list();
  ~planets_list();

  void thread_main();

  basic_list model;

private:

  std::promise<void> m_notify_to_exit;
  std::thread m_thr; /* keep as final member, to avoid race condition */
};

}


#endif

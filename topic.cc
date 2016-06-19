#include "Topic.h"

#include "wamp_session.h"
#include "Logger.h"

#include <iostream>
#include <memory>

namespace XXX {


void topic::add_observer(observer* ptr)
{
  m_observers.push_back(ptr);
}

void topic::notify(const jalson::json_value& patch)
{

  for (auto & item : m_observers2)
  {
    item.second(this, patch);
  }


}


void text_topic::update(const char* newstr)
{
  // create a patch
  jalson::json_value patch = jalson::json_value::make_array();
  jalson::json_object& operation = patch.append_object();
  operation["op"]   = "replace";
  operation["path"] = "";
  operation["value"] = newstr;

  // TODO: for safety, should test the application of the patch

  m_text = newstr;
  notify( patch );
}


jalson::json_value text_topic::snapshot() const
{
  return jalson::json_value::make_string("TODO");
}




} // namespace XXX

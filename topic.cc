#include "topic.h"

#include "wamp_session.h"
#include "Logger.h"
#include "dealer_service.h"

#include <iostream>
#include <memory>

namespace XXX {



data_model_base::data_model_base(std::string model_type)
  : m_model(jalson::json_value::make_object()),
    m_head(&jalson::insert_object(m_model.as_object(),"head")),
    m_body(&jalson::insert_object(m_model.as_object(),"body"))
{
  m_head->insert(std::make_pair("type", std::move(model_type)));
  m_head->insert(std::make_pair("version", 0));
}

data_model_base::~data_model_base()
{
}

void data_model_base::add_publisher(topic* tp)
{
  m_publishers.push_back(tp);
}


void data_model_base::apply_model_patch(const jalson::json_array& patch)
{
  m_model.patch( patch );
  for (auto item : m_publishers)
    item->publish_update( patch );
}

basic_text_model::basic_text_model()
  : data_model_base("basic_text"),
    m_value( & (body().insert(std::make_pair("value", jalson::json_value::make_string())).first->second.as_string()) )
{
}

basic_text_model::basic_text_model(std::string t)
  : data_model_base("basic_text"),
    m_value( & (body().insert(std::make_pair("value", jalson::json_value(std::move(t)))).first->second.as_string()) )
{
}

void basic_text_model::set_value(std::string new_content)
{
  // create a patch
  jalson::json_array patch;
  jalson::json_object& operation = jalson::append_object(patch);
  operation["op"]   = "replace";
  operation["path"] = "/body/value";
  operation["value"] = std::move(new_content);

  apply_model_patch( patch );

  m_value  = &(body()["value"].as_string());
}

const std::string& basic_text_model::get_value() const
{
  return *m_value;
}


topic::topic(std::string uri,
                                 data_model_base * model)
  : m_uri(uri),
    m_model(model)
{
  m_model->add_publisher(this);
}


void topic::add_wamp_session(std::weak_ptr<wamp_session> wp)
{
  m_sessions.push_back(wp);
}


void topic::add_target(std::string realm,
                                 dealer_service* dealer)
{
  m_dealers.push_back(  std::make_tuple(realm,dealer) );
}



void topic::publish_update(const jalson::json_array& patch)
{
  jalson::json_object options;
  XXX::wamp_args pub_args;
  pub_args.args_list = patch;

  for (auto & wp : m_sessions)
    if (auto sp = wp.lock())
    {
      std::cout << "sending update\n";
      sp->publish(m_uri,
                  jalson::json_object(),
                  pub_args);
    }

  for (auto & item : m_dealers)
  {
    std::get<1>(item)->publish(m_uri,
                               std::get<0>(item),
                               options,
                               pub_args);
  }
}

} // namespace XXX

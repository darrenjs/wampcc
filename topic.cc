#include "topic.h"

#include "wamp_session.h"
#include "logger.h"
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


void data_model_base::apply_model_patch(const jalson::json_array& patch,
                                        const jalson::json_array& event)
{
  m_model.patch( patch );
  for (auto item : m_publishers)
    item->publish_update( patch, event);
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

  // TODO: add event
  apply_model_patch( patch, jalson::json_array() );

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
  m_options["_p"]=1;
  m_model->add_publisher(this);
}


void topic::add_wamp_session(std::weak_ptr<wamp_session> wp)
{
  // TODO: need to add snapshot here?
  m_sessions.push_back(wp);
}


void topic::add_target(std::string realm,
                       dealer_service* dealer)
{
  // generate the initial snapshot
  XXX::wamp_args pub_args;
  pub_args.args_list = jalson::json_array();

  jalson::json_array patch;
  jalson::json_object& operation = jalson::append_object(patch);
  operation["op"]   = "replace";
  operation["path"] = "";  /* replace whole document */
  operation["value"] = m_model->model();

  pub_args.args_list.as_array().push_back(std::move(patch));
  pub_args.args_list.as_array().push_back(jalson::json_array());

  dealer->publish(m_uri,
                  realm,
                  m_options,
                  pub_args);

  m_dealers.push_back( std::make_tuple(realm,dealer) );
}


void topic::publish_update(const jalson::json_array& patch,
                           const jalson::json_array& event)
{
  XXX::wamp_args pub_args;
  pub_args.args_list = jalson::json_array();
  pub_args.args_list.as_array().push_back(patch);
  pub_args.args_list.as_array().push_back(event);

  for (auto & wp : m_sessions)
    if (auto sp = wp.lock())
    {
      sp->publish(m_uri,
                  m_options,
                  pub_args);
    }

  for (auto & item : m_dealers)
  {
    std::get<1>(item)->publish(m_uri,
                               std::get<0>(item),
                               m_options,
                               pub_args);
  }
}


basic_list_model::basic_list_model()
  : data_model_base("basic_list_model"),
    m_value( & (body().insert(std::make_pair("value", jalson::json_value::make_array())).first->second.as_array()) )
{
}


void basic_list_model::insert(size_t pos, jalson::json_value val)
{
  // create a patch
  jalson::json_array patch;
  jalson::json_object& operation = jalson::append_object(patch);
  operation["op"]   = "add";
  operation["path"] = "/body/value/" + std::to_string(pos);
  operation["value"] = std::move(val);

  // create event
  jalson::json_array event;
  event.push_back("ins");
  event.push_back(pos);

  apply_model_patch( patch, event );
 }


 void basic_list_model::push_back(jalson::json_value val)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]   = "add";
   operation["path"] = "/body/value/" + std::to_string(m_value->size());
   operation["value"] = std::move(val);

  // create event
  jalson::json_array event;
  event.push_back("append");

   apply_model_patch( patch, event );
 }


 void basic_list_model::erase(size_t index)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]   = "remove";
   operation["path"] = "/body/value/" + std::to_string(index);

   // create event
   jalson::json_array event;
   event.push_back("rm");
   event.push_back(index);
   apply_model_patch( patch, event );
 }


 void basic_list_model::replace(size_t index, jalson::json_value val)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]    = "replace";
   operation["path"]  = "/body/value/" + std::to_string(index);
   operation["value"] = std::move(val);

   // TODO: complete the event
   jalson::json_array event;

   apply_model_patch( patch, event );
}

void basic_list_model::apply_event(const jalson::json_object& /*details*/,
                                   const jalson::json_array& args_list,
                                   const jalson::json_object& /*args_dict*/)
{
  // TODO: check presnece of both items
  // update the model

  if (args_list.size() == 1 && args_list[0].is_array())
  {
    apply_model_patch(args_list[0].as_array(), jalson::json_array());
  }
  else if (args_list.size() > 1 && args_list[0].is_array() && args_list[1].is_array())
  {
    apply_model_patch(args_list[0].as_array(), args_list[1].as_array());
  }

  // TODO: fire events
}




void base_model_subscription::subscribe(std::shared_ptr<XXX::wamp_session>& ws,
                                        model_update_fn model_fn)
{
  auto fn = [=](XXX::subscription_event_type evtype,
                const std::string& /*uri*/,
                const jalson::json_object& details,
                const jalson::json_array& args_list,
                const jalson::json_object& args_dict,
                void* /*user*/)
    {
      std::cout << "got event: " << evtype << ": ";

      if (args_list.size()>0)
        std::cout << args_list[0];


      std::cout << "\n";

      if (evtype == e_sub_update)
        model_fn(details, args_list, args_dict);
    };

  jalson::json_object sub_options;
  sub_options["_p"]=1;

  std::cout << "making subscription: " << m_uri << "\n";
  ws->subscribe(m_uri, sub_options, std::move(fn), nullptr);
}



} // namespace XXX

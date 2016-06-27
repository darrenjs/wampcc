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
  jalson::json_object& operation = jalson::append_object(pub_args.args_list.as_array());
  operation["op"]   = "replace";
  operation["path"] = "";  /* replace whole document */
  operation["value"] = m_model->model();
  dealer->publish(m_uri,
                  realm,
                  m_options,
                  pub_args);

  m_dealers.push_back( std::make_tuple(realm,dealer) );
}



void topic::publish_update(const jalson::json_array& patch)
{
  XXX::wamp_args pub_args;
  pub_args.args_list = patch;

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

  apply_model_patch( patch );
 }

 void basic_list_model::push_back(jalson::json_value val)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]   = "add";
   operation["path"] = "/body/value/" + std::to_string(m_value->size());
   operation["value"] = std::move(val);

   apply_model_patch( patch );
 }

 void basic_list_model::erase(size_t index)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]   = "remove";
   operation["path"] = "/body/value/" + std::to_string(index);

   apply_model_patch( patch );
 }

 void basic_list_model::replace(size_t index, jalson::json_value val)
 {
   // create a patch
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]    = "replace";
   operation["path"]  = "/body/value/" + std::to_string(index);
   operation["value"] = std::move(val);

   apply_model_patch( patch );
}



  topic_subscriber::topic_subscriber(std::string ,
                                     data_model_base* m)
    : m_model(m)
  {
  }

  void topic_subscriber::subscribe(std::shared_ptr<XXX::wamp_session> ws)
  {
    jalson::json_object sub_options;
    sub_options["_p"]=1;

    auto fn = [this](XXX::subscription_event_type evtype,
                   const std::string& uri ,
                   const jalson::json_object& details ,
                   const jalson::json_array& args_list,
                   const jalson::json_object& args_dict,
                   void* user)
      {
        this->subscribe_cb(evtype, uri, details, args_list, args_dict, user);
      };
    ws->subscribe("planets", sub_options, fn, nullptr);

  }



/* called upon subscribed and update events */
void topic_subscriber::subscribe_cb(XXX::subscription_event_type evtype,
                                   const std::string& /* uri */,
                                   const jalson::json_object& /* details */,
                                   const jalson::json_array& args_list,
                                   const jalson::json_object& args_dict,
                                   void* /*user*/)
{

  std::cout << "received topic update!!! evtype: " << evtype << ", args_list: " << args_list
            << ", args_dict:" << args_dict << "\n";
}







} // namespace XXX

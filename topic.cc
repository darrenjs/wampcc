#include "topic.h"

#include "wamp_session.h"
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

jalson::json_value data_model_base::copy_document() const
{
  std::unique_lock<std::mutex> guard(m_lock);
  return m_model;
}


void data_model_base::add_publisher(topic* tp)
{
  m_publishers.push_back(tp);
}


void data_model_base::apply_model_patch(const jalson::json_array& patch,
                                        const jalson::json_array& event)
{
  {
    std::unique_lock<std::mutex> guard(m_lock);
    m_model.patch( patch );
  }
  for (auto item : m_publishers)
    item->publish_update( patch, event);
}

basic_text_model::basic_text_model()
  : data_model_base("basic_text"),
    m_value( & (m_body->insert(std::make_pair("value", jalson::json_value::make_string())).first->second.as_string()) )
{
}

basic_text_model::basic_text_model(std::string t)
  : data_model_base("basic_text"),
    m_value( & (m_body->insert(std::make_pair("value", jalson::json_value(std::move(t)))).first->second.as_string()) )
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

  m_value  = &(m_body->operator[]("value").as_string());
}

const std::string& basic_text_model::get_value() const
{
  return *m_value;
}


topic::topic(std::string uri,
             data_model_base * model)
  : m_uri(uri),
    m_data_model(model)
{
  m_options["_p"]=1;
  m_data_model->add_publisher(this);
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
  operation["value"] = m_data_model->copy_document();

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


const std::string basic_list_model::key_insert("i");
const std::string basic_list_model::key_remove("e");
const std::string basic_list_model::key_modify("m");


basic_list_model::basic_list_model()
  : data_model_base("basic_list_model"),
    m_value( & (m_body->insert(std::make_pair("value", jalson::json_value::make_array())).first->second.as_array()) )
{
}

jalson::json_array basic_list_model::copy_value() const
{
  std::unique_lock<std::mutex> guard(m_lock);
  return  * m_value;
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
  event.push_back(key_insert);
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
  event.push_back( key_insert );
  event.push_back( m_value->size() );

   apply_model_patch( patch, event );
 }


 void basic_list_model::erase(size_t index)
 {
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]   = "remove";
   operation["path"] = "/body/value/" + std::to_string(index);

   jalson::json_array event;
   event.push_back(key_remove);
   event.push_back(index);

   apply_model_patch( patch, event );
 }


 void basic_list_model::replace(size_t index, jalson::json_value val)
 {
   jalson::json_array patch;
   jalson::json_object& operation = jalson::append_object(patch);
   operation["op"]    = "replace";
   operation["path"]  = "/body/value/" + std::to_string(index);
   operation["value"] = std::move(val);

   jalson::json_array event;
   event.push_back(key_modify);
   event.push_back(index);

   apply_model_patch( patch, event );
}

std::vector< jalson::json_value > basic_list_target::copy() const
{
  std::unique_lock<std::mutex> guard(m_mutex);
  return m_items;
}


void basic_list_target::on_insert(size_t i, jalson::json_value v)
{
  static auto fn = [](observer& ob, size_t i){if (ob.on_insert) ob.on_insert(i);};

  {
    std::unique_lock<std::mutex> guard(m_mutex);

    if (m_items.size() >= i )
      m_items.insert(m_items.begin() + i, std::move(v));
    else
      throw basic_list_model::index_error(i, basic_list_model::index_error::eInsert);
  }
  m_observers.notify(fn, i);
}

void basic_list_target::on_remove(size_t i)
{
  static auto fn = [](observer& ob, size_t i){if (ob.on_remove) ob.on_remove(i);};

  {
    std::unique_lock<std::mutex> guard(m_mutex);

    if (m_items.size() > i)
      m_items.erase(m_items.begin() + i);
    else
      throw basic_list_model::index_error(i, basic_list_model::index_error::eRemove);
  }
  m_observers.notify(fn, i);
}

void basic_list_target::on_modify(size_t i, jalson::json_value v)
{
  static auto fn = [](observer& ob, size_t i){if (ob.on_modify) ob.on_modify(i);};

  {
    std::unique_lock<std::mutex> guard(m_mutex);
    if (m_items.size() > i)
      m_items.at(i) = std::move(v);
    else
      throw basic_list_model::index_error(i, basic_list_model::index_error::eModify);
  }
  m_observers.notify(fn, i);

}

void basic_list_target::on_reset(const jalson::json_array & src)
{
  static auto fn = [](observer& ob){if (ob.on_reset) ob.on_reset();};

  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_items = src;
  }
  m_observers.notify(fn);
}


} // namespace XXX

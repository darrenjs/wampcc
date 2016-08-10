#include "XXX/topic.h"

#include "XXX/wamp_session.h"
#include "XXX/dealer_service.h"

#include <iostream>
#include <memory>

namespace XXX {

const std::string basic_text::key_reset("x");

const std::string basic_list::key_reset("x");
const std::string basic_list::key_insert("i");
const std::string basic_list::key_remove("e");
const std::string basic_list::key_modify("m");


basic_text::basic_text(std::string s)
  : m_impl( std::move(s) )
{
}


std::string basic_text::value() const
{
  std::unique_lock<std::mutex> rguard(m_read_mutex);
  return m_impl;
}


void basic_text::assign(std::string s)
{
  static auto fn = [](observer& ob, const std::string& val)
    { ob.on_change(val); };

  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);
    m_impl = std::move(s);
  }

  m_observers.notify( fn, m_impl );
}


void basic_text::add_observer(observer)
{
  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);
  std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);
}


void basic_text::add_observer(patch_observer pub)
{
  observer ob;

  ob.on_change = [pub](const std::string& val)
    {
      jalson::json_array patch;
      jalson::json_object& operation = jalson::append_object(patch);
      operation["op"]    = "replace";
      operation["path"]  = "/body/value";
      operation["value"] = val;

      pub.on_update(patch, { key_reset });
    };


  jalson::json_value model = jalson::json_value::make_object();
  jalson::json_array patch;


  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);

    // obtain snapshot
    jalson::json_object & head = insert_object(model.as_object(), "head");
    jalson::json_object & body = insert_object(model.as_object(), "body");
    head["type"] = "basic_text";
    head["version"] = 0;
    body["value"] = m_impl;

    jalson::json_object& operation = jalson::append_object(patch);
    operation["op"]   = "replace";
    operation["path"] = "";  /* replace whole document */
    operation["value"] = std::move(model);
  }

  pub.on_snapshot(patch);
  m_observers.add(std::move(ob));
}


void topic::add_publisher(std::weak_ptr<wamp_session> wp)
{
  patch_observer obs;

  obs.on_snapshot = [=](const jalson::json_array& patch)
    {
      XXX::wamp_args pub_args;
      pub_args.args_list = jalson::json_array();
      pub_args.args_list.as_array().push_back( patch );

      if (auto sp = wp.lock())
        sp->publish( m_uri, { {KEY_PATCH, 1}, {KEY_SNAPSHOT, 1} },
                     std::move(pub_args) );
    };

  obs.on_update = [=](const jalson::json_array& patch,
                      const jalson::json_array& event)
    {
      XXX::wamp_args pub_args;
      pub_args.args_list = jalson::json_array();
      pub_args.args_list.as_array().push_back( patch );
      pub_args.args_list.as_array().push_back( event );

      if (auto sp = wp.lock())
        sp->publish( m_uri, { {KEY_PATCH, 1} }, std::move(pub_args) );
    };

  m_attach_to_model( std::move(obs) );
}


void topic::add_publisher(std::string realm,
                          std::weak_ptr<dealer_service> dealer)
{
  patch_observer obs;

  obs.on_snapshot = [=](const jalson::json_array& patch)
    {
      XXX::wamp_args pub_args;
      pub_args.args_list = jalson::json_array();
      pub_args.args_list.as_array().push_back( patch );

      if (auto sp=dealer.lock())
        sp->publish( m_uri,
                     realm,
                     { {KEY_PATCH, 1}, {KEY_SNAPSHOT, 1} },
                     std::move(pub_args) );
    };

  obs.on_update = [=](const jalson::json_array& patch,
                      const jalson::json_array& event)
    {
      XXX::wamp_args pub_args;
      pub_args.args_list = jalson::json_array();
      pub_args.args_list.as_array().push_back( patch );
      pub_args.args_list.as_array().push_back( event );

      if (auto sp=dealer.lock())
        sp->publish( m_uri,
                     realm,
                     { {KEY_PATCH,1} },
                     std::move(pub_args) );
    };

  m_attach_to_model( std::move(obs) );
}


jalson::json_array basic_list::copy_value() const
{
  std::unique_lock<std::mutex> rguard(m_read_mutex);
  return m_items;
}


void basic_list::insert(size_t pos, jalson::json_value val)
{
  std::lock(m_write_mutex, m_read_mutex);
  insert_impl(pos, std::move(val));
}


void basic_list::push_back(jalson::json_value val)
{
  std::lock(m_write_mutex, m_read_mutex);
  insert_impl(m_items.size(), std::move(val));
}


void basic_list::insert_impl(size_t pos, jalson::json_value val)
{
  static auto fn = [](list_events& ob, size_t i, const jalson::json_value& v)
    {
      ob.on_insert(i, v);
    };

  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);
    if (m_items.size() >= pos )
    {
      m_items.insert(m_items.begin() + pos, val);
    }
    else throw bad_index(pos);
  }

  m_observers.notify( fn, pos, val );
}


void basic_list::replace(size_t pos, jalson::json_value val)
{
  static auto fn = [](list_events& ob, size_t i, const jalson::json_value& v)
    {
      ob.on_replace(i, v);
    };

  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);
    if (m_items.size() > pos )
    {
      m_items[pos] = val;
    }
    else throw bad_index(pos);
  }

  m_observers.notify( fn, pos, val );
}


void basic_list::erase(size_t pos)
{
  static auto fn = [](list_events& ob, size_t i)
    {
      ob.on_erase(i);
    };

  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);

    if (m_items.size() > pos)
    {
      m_items.erase(m_items.begin() + pos);
    }
    else throw bad_index(pos);
  }
  m_observers.notify( fn, pos );
}


void basic_list::reset(const internal_impl& value)
{
  static auto fn = [](list_events& ob, const internal_impl& src)
    {
      ob.on_reset(src);
    };

  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);
    m_items = value;
  }

  m_observers.notify( fn, value );
}


void basic_list::add_observer(list_events h)
{
  std::unique_lock<std::mutex> wguard(m_write_mutex);
  m_observers.add(std::move(h));
}


void basic_list::add_observer(patch_observer pub)
{
  list_events h;

  h.on_insert = [pub](size_t pos, const jalson::json_value& val)
    {
      jalson::json_array patch;
      jalson::json_object& operation = jalson::append_object(patch);
      operation["op"]    = "add";
      operation["path"]  = "/body/value/" + std::to_string(pos);
      operation["value"] = val;

      pub.on_update(patch, { key_insert, pos });
    };

  h.on_replace = [pub](size_t pos, const jalson::json_value& val)
    {
      jalson::json_array patch;
      jalson::json_object& operation = jalson::append_object(patch);
      operation["op"]    = "replace";
      operation["path"]  = "/body/value/" + std::to_string(pos);
      operation["value"] = std::move(val);

      pub.on_update(patch, { key_modify, pos });
    };

  h.on_erase = [pub](size_t pos)
    {
      jalson::json_array patch;
      jalson::json_object& operation = jalson::append_object(patch);
      operation["op"]   = "remove";
      operation["path"] = "/body/value/" + std::to_string(pos);

      pub.on_update(patch, { key_remove, pos });
    };

  h.on_reset = [pub](const internal_impl& value)
    {
      jalson::json_array patch;
      jalson::json_object& operation = jalson::append_object(patch);
      operation["op"]   = "replace";
      operation["path"] = "/body/value";
      operation["value"] = value;

      pub.on_update(patch, { key_reset } );
    };

  jalson::json_value model = jalson::json_value::make_object();
  jalson::json_array patch;

  std::lock(m_write_mutex, m_read_mutex);
  std::unique_lock<std::mutex> wguard(m_write_mutex, std::adopt_lock);

  {
    std::unique_lock<std::mutex> rguard(m_read_mutex,  std::adopt_lock);

    // obtain snapshot
    jalson::json_object & head = insert_object(model.as_object(), "head");
    jalson::json_object & body = insert_object(model.as_object(), "body");
    head["type"] = "basic_list";
    head["version"] = 0;
    body["value"] = m_items;

    jalson::json_object& operation = jalson::append_object(patch);
    operation["op"]   = "replace";
    operation["path"] = "";  /* replace whole document */
    operation["value"] = std::move(model);
  }

  pub.on_snapshot(patch);
  m_observers.add(std::move(h));
}



} // namespace XXX

#include "XXX/data_model.h"
#include "XXX/dealer_service.h"


namespace XXX {

data_model::data_model()
{
   std::cout << "data_model::data_model()" << std::endl;
}


// TODO: dont think I can have this kind of copy constructor anymore, because
// now the datamodel owns the publishers ... i.e. a copy constructor that also copies the wamp_sessions

// TODO: think about whether it makes sense to copy a data-model, including its
// publishers, although, also consider the need for techincal copies (eg when adding things to a vector etc) ,,, prefer a move


data_model::data_model(const data_model& rhs)
{
   std::cout << "data_model::data_model(copy)" << std::endl;
}


data_model::~data_model()
{
}


model_publisher* data_model::create_publisher(std::string topic_uri)
{
  std::unique_ptr<model_publisher> uptr(new model_publisher(topic_uri, this));

  model_publisher* ptr = uptr.get();

  {
    std::lock_guard<std::mutex> guard(m_publishers_mutex);
    m_publishers.push_back(std::move(uptr));
  }

  return ptr;
}

//======================================================================

XXX::wamp_args model_publisher::prepare_snapshot()
{
  jalson::json_array patch;

  auto model_snapshot = m_data_model->snapshot();

  jalson::json_object& operation = jalson::append_object(patch);
  operation["op"]    = "replace";
  operation["path"]  = "";  /* replace whole document */
  operation["value"] = std::move(model_snapshot);

  XXX::wamp_args pub_args;
  pub_args.args_list.push_back( std::move(patch) );

  return pub_args;
}


// TODO: once we have common base class for both wamp_session &
// internal_session, then only one method will be required here.

void model_publisher::add_publisher(std::weak_ptr<wamp_session> wp)
{
  std::lock_guard<std::mutex> guard(m_data_model->publisher_mutex());

  XXX::wamp_args pub_args = prepare_snapshot();

  if (auto sp = wp.lock())
  {
    sp->publish(m_uri, { {KEY_PATCH, 1}, {KEY_SNAPSHOT, 1} },
                std::move(pub_args) );
    m_sessions.push_back(sp);
  }
}


void model_publisher::add_publisher(std::string realm,
                                    std::weak_ptr<dealer_service> dealer)
{
  std::lock_guard<std::mutex> guard(m_data_model->publisher_mutex());

  XXX::wamp_args pub_args = prepare_snapshot();

  if (auto sp = dealer.lock())
  {
    sp->publish(realm, m_uri, { {KEY_PATCH, 1}, {KEY_SNAPSHOT, 1} },
                std::move(pub_args) );
    m_dealers.push_back({realm,sp});
  }
}


void model_publisher::publish_update(jalson::json_array patch,
                                     jalson::json_array event)
{
  XXX::wamp_args pub_args;
  pub_args.args_list.push_back( std::move(patch) );
  pub_args.args_list.push_back( std::move(event) );

  jalson::json_object options{ {KEY_PATCH,1} };

  for (auto & item : m_dealers)
  {
    if (auto sp = item.second.lock())
      try {
        std::cout << "calling dealer publish " << std::endl;
        sp->publish(item.first, m_uri, options, pub_args);
      } catch (...) { /* ignore */ }
  }

  for (auto & item : m_sessions)
  {
    if (auto sp = item.lock())
      try {
        std::cout << "calling wamp_session publish " << std::endl;
        sp->publish(m_uri, options, pub_args);
      } catch (...) { /* ignore */ }
  }
}

//======================================================================

string_model::string_model(std::string s)
  : m_value( std::move(s) )
{
}


string_model::string_model(const string_model& src)
  : data_model(src),
    m_value(src.value())
{
}


std::string string_model::value() const
{
  std::lock_guard<std::mutex> guard(m_value_mutex);
  return m_value;
}


void string_model::assign(std::string s)
{
  std::string tmp;
  std::lock_guard<std::mutex> publisher_guard(m_publishers_mutex);
  {
    std::lock_guard<std::mutex> value_guard(m_value_mutex);
    if (m_value == s)
      return;
    tmp = s;
    m_value = std::move(s);
  }

  if (!m_publishers.empty())
  {
    /* Create publication, which comprises two parts:
       (1) the json-model patch
       (2) the rich-model event description.
    */
    jalson::json_array patch;
    jalson::json_object& operation = jalson::append_object(patch);
    operation.insert({"op","replace"});
    operation.insert({"path","/body/value"});
    operation.insert({"value",std::move(tmp)});

    // string_model model is so simple that an event description is not needed
    jalson::json_array event;

    // push the update to all model publishers
    for (auto & publisher : m_publishers)
      try {
        publisher->publish_update(patch, event);
      }
      catch (...) { /* ignore exceptions */ }
  }
}


jalson::json_value string_model::snapshot() const
{
  jalson::json_value jmodel = jalson::json_value::make_object();
  jalson::json_object & head = insert_object(jmodel.as_object(), "head");
  jalson::json_object & body = insert_object(jmodel.as_object(), "body");
  head.emplace("type",   "string_model");
  head.emplace("version", 0);
  auto iter = body.insert({"value",jalson::json_string()}).first;

  {
    std::lock_guard<std::mutex> guard(m_value_mutex);
    iter->second.as_string() = m_value;
  }

  return jmodel;
}

//======================================================================


model_sub_base::model_sub_base(std::shared_ptr<XXX::wamp_session>& ws,
                               std::string topic_uri)
  : m_uri(topic_uri),
    m_session(ws)
{
}


model_sub_base::~model_sub_base()
{
}



void jmodel_subscription::on_update(jalson::json_object options,
                                    wamp_args args)
{
  std::cout << "got jmodel update, " << args.args_list << std::endl;
  if (options.find(KEY_PATCH) != options.end())
  {
    auto & patchset = args.args_list[0].as_array();
    {
      std::lock_guard<std::mutex> guard(m_value_mutex);
      m_value.patch(patchset);
      std::cout << "model is now: " << m_value << std::endl;
    }
    //m_observer.on_change();
  }
  else
  {
    // TODO: raise an error?
  }
}

//======================================================================


void string_subscription::on_update(jalson::json_object options,
                                    wamp_args args)
{
  /* EV thread */

  /* Note, the string_model model is so simple that an event description is not
   * needed */
  const jalson::json_array * patchset = nullptr;
  if (args.args_list.size() > 0 && args.args_list[0].is_array())
    patchset = &args.args_list[0].as_array();

  // TODO: this will be a common pattern to check for a snapshot
  if ( patchset &&
       (patchset->size()==1) &&
       (options.find(KEY_SNAPSHOT) != options.end()) && // is snapshot
       patchset->operator[](0).is_object()
    )
  { //   [ patch ]
    const auto & patch       = patchset->operator[](0).as_object();
    const auto & patch_value = jalson::get_ref(patch, "value").as_object();
    const auto & body        = jalson::get_ref(patch_value, "body").as_object();
    const auto & body_value  = jalson::get_ref(body, "value").as_string();

    {
      std::lock_guard<std::mutex> guard(m_value_mutex);
      m_value = body_value;
    }
    std::cout << "string_model_sub, snapshot=" << m_value << std::endl;
    m_observer.on_change(*this);
  }
  else if (patchset)
  {
    const auto & patch = patchset->operator[](0).as_object();
    auto value = std::move(jalson::get_ref(patch, "value").as_string());

    {
      std::lock_guard<std::mutex> guard(m_value_mutex);
      m_value = std::move(value);
    }

    std::cout << "string_model_sub, update=" << m_value << std::endl;
    m_observer.on_change(*this);
  }
}


} // namespace

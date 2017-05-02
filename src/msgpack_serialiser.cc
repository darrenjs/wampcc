/*
 * Copyright (c) 2017 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "msgpack.h"

#include <iostream>
#include <stack>
#include <sstream>

//#define WAMPCC_TRACE_MSGPACK

namespace wampcc
{

static void free_msgpack_bytes(region* ptr)
{
  if (ptr)
    ::free(ptr->first);
}

msgpack_encoder::msgpack_encoder() : m_packer(m_sbuf) {}

typedef uint32_t t_msgpack_size;

std::unique_ptr<region, void (*)(region*)> msgpack_encoder::encode(
    const json_value& src)
{
  pack_value(src);
  size_t len = m_sbuf.size(); // size() must be called before release()
  return {new region(m_sbuf.release(), len), free_msgpack_bytes};
}

void msgpack_encoder::pack_string(const std::string& s)
{
  if (s.size() > std::numeric_limits<t_msgpack_size>::max())
    throw msgpack_error("string exceeds msgpack max size");

#ifdef WAMPCC_TRACE_MSGPACK
  std::cout << "pack_str (len " << s.size() << ")" << std::endl;
#endif
  m_packer.pack_str(s.size());

#ifdef WAMPCC_TRACE_MSGPACK
  std::cout << "pack_str_body" << std::endl;
#endif
  m_packer.pack_str_body(s.c_str(), s.size());
}

void msgpack_encoder::pack_object(const json_object& jobject)
{
#ifdef WAMPCC_TRACE_MSGPACK
  std::cout << "pack_map(items " << jobject.size() << ")" << std::endl;
#endif
  m_packer.pack_map(jobject.size());

  for (auto& item : jobject) {
    pack_string(item.first);
    pack_value(item.second);
  }
}

void msgpack_encoder::pack_array(const json_array& ja)
{
  if (ja.size() > std::numeric_limits<t_msgpack_size>::max())
    throw msgpack_error("json_array exceeds msgpack max size");

#ifdef WAMPCC_TRACE_MSGPACK
  std::cout << "pack_array(items " << ja.size() << ")" << std::endl;
#endif
  m_packer.pack_array(ja.size());
  for (auto& item : ja)
    pack_value(item);
}

void msgpack_encoder::pack_value(const json_value& jv)
{
  switch (jv.type()) {
    case wampcc::eNULL: {
#ifdef WAMPCC_TRACE_MSGPACK
      std::cout << "pack_nil" << std::endl;
#endif
      m_packer.pack_nil();
      break;
    }
    case wampcc::eOBJECT: {
      pack_object(jv.as_object());
      break;
    }
    case wampcc::eARRAY: {
      pack_array(jv.as_array());
      break;
    }
    case wampcc::eSTRING: {
      pack_string(jv.as_string());
      break;
    }
    case wampcc::eBOOL: {
      if (jv.as_bool() == true) {
#ifdef WAMPCC_TRACE_MSGPACK
        std::cout << "pack_true" << std::endl;
#endif
        m_packer.pack_true();
      } else {
#ifdef WAMPCC_TRACE_MSGPACK
        std::cout << "pack_false" << std::endl;
#endif
        m_packer.pack_false();
      }
      break;
    }
    case wampcc::eREAL: {
#ifdef WAMPCC_TRACE_MSGPACK
      std::cout << "pack_double" << std::endl;
#endif
      m_packer.pack_double(jv.as_real());
      break;
    }
    case wampcc::eINTEGER: {
      if (jv.is_int()) {
#ifdef WAMPCC_TRACE_MSGPACK
        std::cout << "pack_long_long" << std::endl;
#endif
        m_packer.pack_int(jv.as_int());
      } else {
#ifdef WAMPCC_TRACE_MSGPACK
        std::cout << "pack_unsigned_long_long" << std::endl;
#endif
        m_packer.pack_unsigned_long_long(jv.as_uint());
      }
      break;
    }
  }
}

class msgpack_visitor
{
public:
  /* Add the currently parsed json_value into the json document, which means we
   * either add it to a parent array, or to a parent object, or if we are
   * parsing a map-key, we use it for a mapkey. */
  json_value* add(json_value&& jv)
  {
    switch (m_parse_mode) {
      case parse_mode::init: {
        m_root = std::move(jv);
        m_parse_mode = parse_mode::undef;
        return &m_root;
      }
      case parse_mode::undef: {
        throw msgpack_error("add json_value called for undefied parse_mode");
      }
      case parse_mode::array: {
        if (m_containers.empty())
          throw msgpack_error(
              "add array-item attempted without parent container");

        json_array& arr = m_containers.top()->as_array();
        arr.push_back(std::move(jv));
        return &arr.back();
      }
      case parse_mode::object: {
        if (m_containers.empty())
          throw msgpack_error(
              "add object-item attempted without parent container");
        if (!m_have_map_key)
          throw msgpack_error("add object-item attempted without map-key");

        m_have_map_key = false;
        json_object& obj = m_containers.top()->as_object();
        auto ins = obj.insert({std::move(m_map_key), std::move(jv)});
        return &(ins.first->second);
      }
      case parse_mode::mapkey: {
        if (m_have_map_key)
          throw msgpack_error("map-key assigned attempted when map_key already available");

        m_map_key = std::move(jv.as_string());
        m_have_map_key = true;
        return nullptr;
      }
    }
    return nullptr;
  }

  bool visit_boolean(bool v)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ":" << v << std::endl;
#endif
    add(json_value::make_bool(v));
    return true;
  }

  bool visit_nil()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    add(json_value::make_null());
    return true;
  }

  bool visit_float(double v)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ":" << v << std::endl;
#endif
    add(json_value::make_double(v));
    return true;
  }

  bool visit_negative_integer(int64_t v)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ":" << v << std::endl;
#endif
    add(json_value::make_int(v));
    return true;
  }

  bool visit_positive_integer(uint64_t v)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ":" << v << std::endl;
#endif
    add(json_value::make_uint(v));
    return true;
  }

  bool visit_str(const char* v, uint32_t size)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ":" << std::string(v, size)
              << std::endl;
#endif
    add(json_value::make_string(v, size));
    return true;
  }

  bool start_map_key()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::mapkey;
    return true;
  }

  bool end_map_key()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::undef;
    return true;
  }

  bool start_map(uint32_t pairs)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ": items " << pairs
              << std::endl;
    m_indent += "  ";
#endif
    add_container(json_object());
    return true;
  }

  bool end_map()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    m_indent = m_indent.substr(0, m_indent.size() - 2);
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_containers.pop();
    return true;
  }

  bool start_map_value()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::object;
    return true;
  }

  bool end_map_value()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::undef;
    return true;
  }

  bool start_array(uint32_t num_elements)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << ": size " << num_elements
              << std::endl;
    m_indent += "  ";
#endif
    json_array array;
    array.reserve(num_elements);
    add_container(std::move(array));
    return true;
  }

  bool end_array()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    m_indent = m_indent.substr(0, m_indent.size() - 2);
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_containers.pop();
    return true;
  }

  bool start_array_item()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::array;
    return true;
  }

  bool end_array_item()
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    m_parse_mode = parse_mode::undef;
    return true;
  }

  void parse_error(size_t parsed_offset, size_t error_offset)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    throw msgpack_error("parse error when parsing msgpack", parsed_offset,
                        error_offset);
  }

  void insufficient_bytes(size_t parsed_offset, size_t error_offset)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    throw msgpack_error("insufficient bytes when parsing msgpack",
                        parsed_offset, error_offset);
  }

  bool visit_bin(const char* /*v*/, uint32_t /*size*/)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    return true;
  }
  bool visit_ext(const char* /*v*/, uint32_t /*size*/)
  {
#ifdef WAMPCC_TRACE_MSGPACK
    std::cout << m_indent << __FUNCTION__ << std::endl;
#endif
    return true;
  }

  json_value& root() { return m_root; }
  const json_value& root() const { return m_root; }

  bool is_good() const {
    return m_containers.empty() &&
      (m_have_map_key == false) &&
      (m_parse_mode == parse_mode::undef);
  }

private:
  /* Here 'container' is a univeral reference, however we want to restrict this
   * template to accepting only rvalue references. */
  template <typename T, class = typename std::enable_if<
                            !std::is_lvalue_reference<T>::value>::type>
  void add_container(T&& container)
  {
    json_value* p = add(json_value(std::move(container)));
    m_containers.push(p);
  }

  json_value m_root;

#ifdef WAMPCC_TRACE_MSGPACK
  std::string m_indent;
#endif

  std::stack<json_value*> m_containers;

  std::string m_map_key;

  /* Do we have a map-key? */
  bool m_have_map_key = false;

  /* What kind of value is currently being parsed and added to the documet? */
  enum class parse_mode {
    undef,  /* nothing */
    init,   /* the first item */
    array,  /* an array-cell */
    object, /* an object-item (value) */
    mapkey  /* an object-item (key) */
  } m_parse_mode = parse_mode::init;
};

bool msgpack_decoder::decode(const char* src, size_t len)
{
  msgpack_visitor visitor;

  bool success = msgpack::parse<msgpack_visitor>(src, len, visitor);

  if (success && visitor.is_good())
    this->result = std::move(visitor.root());

  return success && visitor.is_good();
}
}

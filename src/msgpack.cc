/*
 * Copyright (c) 2017 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "msgpack.h"

#include <iostream>
#include <stack>

namespace wampcc {

static void mspack_region_free(region * ptr)
{
  if (ptr)
    ::free(ptr->first);
}


msgpack_encoder::msgpack_encoder()
  : m_packer(m_sbuf)
{
}

std::unique_ptr<region, void(*)(region*)> msgpack_encoder::encode(const json_array & src)
{
  pack_array(src);

  size_t len = m_sbuf.size(); // must take size before release() called

  return { new region{m_sbuf.release(), len}, mspack_region_free};
}

void msgpack_encoder::pack_string(const std::string& s)
{
  uint32_t l = s.size();
  // TODO:  msgpack doesn't take size_t, check length?
  m_packer.pack_str(l);
  m_packer.pack_str_body(s.c_str(), l);
}

void msgpack_encoder::pack_object(const json_object & jobject)
{
  for (auto & item : jobject) {
    pack_string(item.first);
    pack_value(item.second);
  }
}


void msgpack_encoder::pack_array(const json_array & ja)
{
  m_packer.pack_array(ja.size());
  for (auto& item : ja) {
    pack_value(item);
  }
}


void msgpack_encoder::pack_value(const json_value & jv)
{
  switch (jv.type())
  {
    case wampcc::eNULL : {
      m_packer.pack_nil();
      break;
    }

    case wampcc::eOBJECT : {
      pack_object(jv.as_object());
      break;
    }

    case wampcc::eARRAY : {
      pack_array(jv.as_array());
      break;
    }

    case wampcc::eSTRING : {
      pack_string(jv.as_string());
      break;
    }

    case wampcc::eBOOL : {
      if (jv.as_bool() == true)
        m_packer.pack_true();
      else
        m_packer.pack_false();
      break;
    }

    case wampcc::eREAL: {
      m_packer.pack_double(jv.as_real());
      break;
    }

    case wampcc::eINTEGER: {
      if (jv.is_int())
        m_packer.pack_long_long(jv.as_int());
      else
        m_packer.pack_unsigned_long_long(jv.as_uint());
      break;
    }

  }
}





class stdout_msgpack_visitor
{
private:
  std::string indent;

public:

  bool visit_boolean(bool v ) {
    std::cout << indent << __FUNCTION__ << ":" << v << std::endl;
    return true;
  }

  bool visit_nil() {
    std::cout << indent << __FUNCTION__ << std::endl;
    return true;
  }

  bool visit_float(double v) {
    std::cout << indent << __FUNCTION__ << ":" << v << std::endl;
    return true;
  }

  bool visit_negative_integer(int64_t v) {
    std::cout << indent << __FUNCTION__ << ":" << v << std::endl;
    return true;
  }

  bool visit_positive_integer(uint64_t v) {
    std::cout << indent << __FUNCTION__ << ":" << v << std::endl;
    return true;
  }

  bool visit_str(const char* v, uint32_t size) {
    std::cout << indent << __FUNCTION__ << ":" << std::string(v, size) << std::endl;
    return true;
  }

  bool start_map_key() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }
  bool end_map_key() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }

  bool start_map(uint32_t num_kv_pairs) {
    std::cout << indent << __FUNCTION__  << ": pairs " << num_kv_pairs << std::endl;
    indent += "  ";
    return true;
  }
  bool end_map() {
    indent = indent.substr(0, indent.size()-2);
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }

  bool start_map_value() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }
  bool end_map_value() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }

  bool start_array(uint32_t num_elements) {
    std::cout << indent << __FUNCTION__ << ": size " << num_elements << std::endl;
    indent += "  ";
    return true;
  }

  bool end_array() {
    indent = indent.substr(0, indent.size()-2);
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }

  bool start_array_item() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }
  bool end_array_item() {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }

  void parse_error(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
  }
  void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
  }

  bool visit_bin(const char* /*v*/, uint32_t /*size*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }
  bool visit_ext(const char* /*v*/, uint32_t /*size*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
    return true;
  }
};



class msgpack_visitor
{
private:
  std::string indent;

  std::stack<json_array*> m_arrays;
  std::stack<json_object*> m_objects;

  // TODO: in json, is it true that keys are always sdtring?
  std::string m_map_key;

  enum class container
  {
    undef,
    array,
    object
  } m_current = container::undef;


  bool m_parsing_map_key = false;

public:

  json_value root;

  void add(json_value&& jv)
  {
    if (m_parsing_map_key) {
      m_map_key = std::move(jv.as_string());
      return;
    }

    switch (m_current) {
      case container::array : {
        // TODO: check not empty
        m_arrays.top()->push_back( std::move(jv) );
        break;
      }
      case container::object : {
        // TODO: check not empty
        m_objects.top()->insert({m_map_key, std::move(jv)});
        break;
      }
      case container::undef : break; // TODO
    }
  }

  bool visit_boolean(bool v ) {
    add(json_value::make_bool(v));
    return true;
  }

  bool visit_nil() {
    add(json_value::make_null());
    return true;
  }

  bool visit_float(double v) {
    add(json_value::make_double(v));
    return true;
  }

  bool visit_negative_integer(int64_t v) {
    add(json_value::make_uint(v));
    return true;
  }

  bool visit_positive_integer(uint64_t v) {
    add(json_value::make_int(v));
    return true;
  }

  bool visit_str(const char* v, uint32_t size) {
    add(json_value::make_string(v,size));
    return true;
  }

  bool start_map_key() {
    m_parsing_map_key = true;
    return true;
  }

  bool end_map_key() {
    m_parsing_map_key = false;
    return true;
  }

  bool start_map(uint32_t num_kv_pairs) {
    if (root == json_value())
      root = json_object();
    m_objects.push(&(root.as_object()));
    return true;
  }

  bool end_map() {
    m_objects.pop();
    return true;
  }

  bool start_map_value() {
    m_current = container::object;
    return true;
  }

  bool end_map_value() {
    m_current = container::undef;
    return true;
  }

  bool start_array(uint32_t num_elements) {
    if (root == json_value())
      root = json_array();
    m_arrays.push(&(root.as_array()));
    return true;
  }

  bool end_array() {
    m_arrays.pop();
    return true;
  }

  bool start_array_item() {
    m_current = container::array;
    return true;
  }

  bool end_array_item() {
    m_current = container::undef;
    return true;
  }

  void parse_error(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
  }

  void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    std::cout << indent << __FUNCTION__  << std::endl;
  }

  bool visit_bin(const char* /*v*/, uint32_t /*size*/) {
    return true;
  }
  bool visit_ext(const char* /*v*/, uint32_t /*size*/) {
    return true;
  }
};


json_value msgpack_decoder::decode(const char * src, size_t len)
{
  msgpack_visitor visitor;
  bool success = msgpack::parse<msgpack_visitor>(src, len, visitor);
  return visitor.root;
}



}


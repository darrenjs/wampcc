/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/http_parser.h"

#include "wampcc/utils.h"
#include "wampcc/websocket_protocol.h"
#include "3rdparty/http_parser/http_parser.h" /* nodejs http parser */

#include <iostream>
#include <string.h>


namespace wampcc
{

unsigned int http_parser::error() const { return m_parser->http_errno; }

bool http_parser::good() const { return error() == HPE_OK; }

bool http_parser::is_upgrade() const { return m_parser->upgrade != 0; }

std::string http_parser::error_text() const
{
  return std::string(
      ::http_errno_description((enum ::http_errno)m_parser->http_errno));
}


http_parser::http_parser(parser_type pt)
  : m_settings(new ::http_parser_settings),
    m_parser(new ::http_parser),
    m_http_status_code(0)
{
  ::http_parser_settings_init(m_settings.get());

  if (pt == e_http_request)
    ::http_parser_init(m_parser.get(), HTTP_REQUEST);
  else if (pt == e_http_response)
    ::http_parser_init(m_parser.get(), HTTP_RESPONSE);

  m_parser->data = this;

  // set up the callbacks, using lambdas without captures, so that these lambdas
  // can be assigned to function pointers.

  m_settings->on_headers_complete = [](::http_parser* p) {
    auto hp = (wampcc::http_parser*)p->data;
    return hp->on_headers_complete();
  };

  m_settings->on_url = [](::http_parser* p, const char* s, size_t n) {
    auto hp = (wampcc::http_parser*)p->data;
    return hp->on_url(s, n);
  };

  m_settings->on_header_field = [](::http_parser* p, const char* s, size_t n) {
    auto hp = (wampcc::http_parser*)p->data;
    return hp->on_header_field(s, n);
  };

  m_settings->on_header_value = [](::http_parser* p, const char* s, size_t n) {
    auto hp = (wampcc::http_parser*)p->data;
    return hp->on_header_value(s, n);
  };

  m_settings->on_status = [](::http_parser* p, const char* s, size_t n) {
    auto hp = (wampcc::http_parser*)p->data;
    return hp->on_status(s, n);
  };
}


http_parser::~http_parser()
{
  /* Need destructor here, even empty, so that when the unique_ptr destructor
   * for http_parser_settings is instantiated it can see the definition of
   * http_parser_settings. */
}

void http_parser::store_current_header_field()
{
  if (!m_current_field.empty()) {
    /* It's possible that a HTTP header field might be duplicated, in which case
     * we combine the values together in a comma separated list. */
    auto it = m_headers.find(m_current_field);
    if (it != m_headers.end()) {
      it->second.append(",");
      it->second.append(std::move(m_current_value));
    } else {
      m_headers.insert({m_current_field, m_current_value});
    }
  }

  m_current_field.clear();
  m_current_value.clear();
}


int http_parser::on_url(const char* s, size_t n) { return 0; }


int http_parser::on_header_field(const char* s, size_t n)
{
  if (m_state == eParsingField) {
    m_current_field += {s, n};
  } else {
    store_current_header_field();
    m_current_field = {s, n};
    m_state = eParsingField;
  }

  return 0;
}


int http_parser::on_header_value(const char* s, size_t n)
{
  if (m_state == eParsingField) {
    m_current_value = {s, n};
    m_state = eParsingValue;
  } else
    m_current_value += {s, n};


  return 0;
}


size_t http_parser::handle_input(char* const data, size_t const len)
{
  if (m_state != eComplete)
    return ::http_parser_execute(m_parser.get(), m_settings.get(), data, len);
  else
    throw std::runtime_error("http parse already complete");
}


int http_parser::on_headers_complete()
{
  store_current_header_field();
  m_state = eComplete;
  m_http_status_code = m_parser->status_code;
  return HPE_OK;
}


int http_parser::on_status(const char* s, size_t n)
{
  m_http_status += {s, n};
  return 0;
}

}

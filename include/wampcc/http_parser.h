/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_HTTP_PARSER_H
#define WAMPCC_HTTP_PARSER_H

#include <map>
#include <string>
#include <memory>
#include <stdexcept>

// types brought in from nodejs http-parser project
struct http_parser;
struct http_parser_settings;

namespace wampcc
{

class http_parser
{
public:
  static constexpr unsigned int status_code_switching_protocols = 101;

  enum parser_type { e_http_request, e_http_response };

  static bool is_http_get(const char* s, size_t n)
  {
    return n > 3 && s[0] == 'G' && s[1] == 'E' && s[2] == 'T' && isspace(s[3]);
  }

  http_parser(parser_type);
  ~http_parser();

  static constexpr const unsigned char HEADER_SIZE = 4; /* "GET " */

  size_t handle_input(char* const, size_t const);

  /** have we completed parsing headers? */
  bool is_complete() const { return m_state == eComplete; }

  /** does header indicate connection upgrade? */
  bool is_upgrade() const;

  /** access the http-parser error code (see nodejs|http_parser.h for codes) */
  unsigned int error() const;

  /** return string associated with any error */
  std::string error_text() const;

  /** does http-parser error indicate success? */
  bool is_good() const;

  /** is field present in headers? field should be lowercase */
  bool has(const char* s) const { return m_headers.find(s) != m_headers.end(); }

  /** return header field, otherwise throw; field should be lowercase */
  const std::string& get(const std::string& field) const
  {
    auto it = m_headers.find(field);
    if (it != m_headers.end())
      return it->second;
    else
      throw std::runtime_error("http header field not found");
  }

  /* HTTP response status-line textual phrase */
  const std::string& http_status_phrase() const { return m_http_status; }

  /* HTTP response status-line code */
  unsigned int http_status_code() const { return m_http_status_code; }

private:
  void store_current_header_field();
  int on_headers_complete();
  int on_url(const char* s, size_t n);
  int on_header_field(const char* s, size_t n);
  int on_header_value(const char* s, size_t n);
  int on_status(const char* s, size_t n);

  std::map<std::string, std::string> m_headers;

  std::unique_ptr<::http_parser_settings> m_settings;
  std::unique_ptr<::http_parser> m_parser;

  enum state { eParsingField = 0, eParsingValue, eComplete };
  state m_state = eParsingField;

  std::string m_current_field;
  std::string m_current_value;

  unsigned int m_http_status_code;
  std::string m_http_status;
};
}


#endif

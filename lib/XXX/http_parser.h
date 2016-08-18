#ifndef XXX_HTTP_PARSER_H
#define XXX_HTTP_PARSER_H

#include <map>
#include <string>
#include <memory>

//types brought in from nodejs http-parser project
struct http_parser;
struct http_parser_settings;

namespace XXX
{

class http_parser
{
 public:

  static bool is_http_get(const char* s, size_t n)
  {
    return n>3 && s[0]=='G' && s[1]=='E' && s[2]=='T' && isspace(s[3]);
  }

  http_parser();
  ~http_parser();

  static constexpr const unsigned char HEADER_SIZE = 4; /* "GET " */

  size_t handle_input(char* const, size_t const);

  /** have we completed parsing headers? */
  bool complete() const { return m_state==eComplete; }

  /** does header indicate connection upgrade? */
  bool is_upgrade() const;

  /** the http-parser error number (see nodejs|http_parser.h for codes) */
  unsigned int error() const;

  /** return string associated with any error */
  std::string error_text() const;

  /** does http-parser error indicate success? */
  bool good() const;

  /** does http-parser error indicate failure? */
  bool fail() const;

  size_t count(const char* s) const { return m_headers.count(s); }

  const std::string& get(const std::string& field) const
  {
    auto it = m_headers.find(field);
    if (it != m_headers.end())
      return it->second;
    else
      throw std::runtime_error("requested http header not found");
  }

 private:

  void store_header();
  int on_headers_complete();
  int on_url(const char *s, size_t n);
  int on_header_field(const char *s, size_t n);
  int on_header_value(const char *s, size_t n);

  std::map<std::string, std::string> m_headers;

  std::unique_ptr<::http_parser_settings> m_settings;
  std::unique_ptr<::http_parser> m_parser;

  enum state
  {
    eParsingField = 0,
    eParsingValue,
    eComplete
  };
  state m_state = eParsingField;

  std::string m_current_field;
  std::string m_current_value;
};

}



#endif

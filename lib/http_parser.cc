
#include "XXX/http_parser.h"

#include "XXX/utils.h"
#include "XXX/websocket_protocol.h"

#include <http_parser.h> /* nodejs http parser */

#include <iostream> // TODO: delete me

#include <string.h>



namespace XXX
{


unsigned int http_parser::error() const {
  return m_parser->http_errno;
}

bool http_parser::good() const {
  return error() == HPE_OK;
}

bool http_parser::fail() const {
  return error() != HPE_OK;
}

bool http_parser::is_upgrade() const {
  return m_parser->upgrade != 0;
}

std::string http_parser::error_text() const {
  return std::string(  ::http_errno_description((enum ::http_errno)m_parser->http_errno) );
}


http_parser::http_parser()
  : m_settings( new ::http_parser_settings ),
    m_parser( new ::http_parser )
{
  ::http_parser_settings_init( m_settings.get() );

  ::http_parser_init(m_parser.get(), HTTP_REQUEST);
  m_parser->data = this;

  // set up the callbacks, using lambdas without captures, so that these lambdas
  // can be assigned to function pointers.

  m_settings->on_headers_complete=[](::http_parser * p) {
    auto hp =(XXX::http_parser*)p->data; return hp->on_headers_complete(); };

  m_settings->on_url=[](::http_parser* p, const char *s, size_t n) {
    auto hp =(XXX::http_parser*)p->data; return hp->on_url(s,n); };

  m_settings->on_header_field=[](::http_parser* p, const char *s, size_t n) {
    auto hp =(XXX::http_parser*)p->data; return hp->on_header_field(s,n); };

  m_settings->on_header_value=[](::http_parser* p, const char *s, size_t n) {
    auto hp =(XXX::http_parser*)p->data; return hp->on_header_value(s,n); };

}


http_parser::~http_parser()
{
}


void http_parser::store_header()
{
  // TODO: if field already exists, append to existing (comma).

  if (!m_current_field.empty())
    m_headers[ m_current_field ] = m_current_value;

  m_current_field.clear();
  m_current_value.clear();
}


int http_parser::on_url(const char *s, size_t n)
{
  return 0;
}


int http_parser::on_header_field(const char *s, size_t n)
{
  if (m_state == eParsingField)
  {
    m_current_field += {s,n};
  }
  else
  {
    store_header();
    m_current_field = {s,n};
    m_state = eParsingField;
  }

  std::cout << "on_header_field ["  << m_current_field << "]\n";

  return 0;
}


int http_parser::on_header_value(const char *s, size_t n)
{
  if (m_state == eParsingField)
  {
    m_current_value = {s,n};
    m_state = eParsingValue;
  }
  else
  {
    m_current_value += {s,n};
  }
  std::cout << "on_header_value [" << m_current_value  << "]\n";
  return 0;
}


size_t http_parser::handle_input(char* const data, size_t const len)
{
  if (m_state != eComplete)
  {
    return ::http_parser_execute(
      m_parser.get(), m_settings.get(),
      data, len);
  }
  else
    throw std::runtime_error("http parse already complete");
}


int http_parser::on_headers_complete()
{
  std::cout << "***** headers complete *****\n";
  store_header();
  m_state = eComplete;
  return HPE_OK;
}


}

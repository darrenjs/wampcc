/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/* The header provides the wampcc types which wrap the websocketpp types  */


#include "wampcc/types.h"

#include "websocketpp/http/request.hpp"
#include "websocketpp/http/response.hpp"
#include "websocketpp/message_buffer/message.hpp"
#include "websocketpp/message_buffer/alloc.hpp"
#include "websocketpp/processors/hybi13.hpp"
#include "websocketpp/random/none.hpp"
#include "websocketpp/extensions/permessage_deflate/disabled.hpp"

namespace wampcc
{

struct websocket_config
{

  typedef websocketpp::http::parser::request request_type;
  typedef websocketpp::http::parser::response response_type;
  typedef websocketpp::message_buffer::message<websocketpp::message_buffer::alloc::con_msg_manager> message_type;
  typedef websocketpp::message_buffer::alloc::con_msg_manager<message_type> con_msg_manager_type;

  typedef websocketpp::random::none::int_generator<uint32_t> rng_type;

  /// permessage_compress extension
  struct permessage_deflate_config {
    typedef websocketpp::http::parser::request request_type;

    /// If the remote endpoint requests that we reset the compression
    /// context after each message should we honor the request?
    static const bool allow_disabling_context_takeover = true;

    /// If the remote endpoint requests that we reduce the size of the
    /// LZ77 sliding window size this is the lowest value that will be
    /// allowed. Values range from 8 to 15. A value of 8 means we will
    /// allow any possible window size. A value of 15 means do not allow
    /// negotiation of the window size (ie require the default).
    static const uint8_t minimum_outgoing_window_bits = 8;
  };

  typedef websocketpp::extensions::permessage_deflate::disabled<permessage_deflate_config> permessage_deflate_type;
    /// Default maximum message size
    /**
     * Default value for the processor's maximum message size. Maximum message size
     * determines the point at which the library will fail a connection with the·
     * message_too_big protocol error.
     *
     * The default is 32MB
     *
     * @since 0.3.0
     */
    static const size_t max_message_size = 32000000;

    /// Global flag for enabling/disabling extensions
    static const bool enable_extensions = true;

};

class websocketpp_impl
{
public:
  websocketpp_impl(connect_mode mode)
  : m_msg_manager( new websocket_config::con_msg_manager_type )
  {
    m_proc.reset(
      new websocketpp::processor::hybi13<websocket_config>(false, mode==connect_mode::passive,
                                                           m_msg_manager,
                                                           m_rng_mgr) );
  }

  websocketpp::processor::processor<websocket_config>* processor() { return m_proc.get(); }

  websocketpp::processor::hybi13<websocket_config>::msg_manager_ptr& msg_manager() { return m_msg_manager; }


  /* Get the frame details of the a message as a string, for logging. */
  static std::string frame_to_string(websocket_config::message_type::ptr&);

private:
  websocket_config::rng_type m_rng_mgr;
  websocketpp::processor::hybi13<websocket_config>::msg_manager_ptr m_msg_manager;
  std::unique_ptr<websocketpp::processor::processor<websocket_config>> m_proc;
};



}

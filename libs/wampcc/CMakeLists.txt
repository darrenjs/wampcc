# source files
file(GLOB LIB_WAMPCC_SRC_FILES ${PROJECT_SOURCE_DIR}/libs/wampcc/*.cc)
file(GLOB LIB_3RDPTY_HTTPPARSER_SRC_FILES ${PROJECT_SOURCE_DIR}/3rdparty/http_parser/*.c)
file(GLOB LIB_3RDPTY_APACH_SRC_FILES ${PROJECT_SOURCE_DIR}/3rdparty/apache/*.c)

# list of headers file to install
set(INSTALL_HDRS
  ${PROJECT_SOURCE_DIR}/include/wampcc/version.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/types.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/kernel.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/wamp_session.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/wamp_router.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/protocol.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/rawsocket_protocol.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/websocket_protocol.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/tcp_socket.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/socket_address.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/data_model.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/error.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/helper.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/wampcc.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/ssl_socket.h
        )

##
## Static library
##
if(BUILD_STATIC_LIBS)
  add_library(wampcc_static STATIC
      ${LIB_WAMPCC_SRC_FILES}
      ${LIB_3RDPTY_HTTPPARSER_SRC_FILES}
      ${LIB_3RDPTY_APACH_SRC_FILES})

  set_target_properties(wampcc_static PROPERTIES OUTPUT_NAME wampcc)

  target_include_directories(wampcc_static
    PUBLIC
      $<INSTALL_INTERFACE:include>
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	PRIVATE
	  ${LIBUV_INCLUDE_DIRS} )

  	target_link_libraries(wampcc_static
      PRIVATE
	    LibUV::LibUV
	    OpenSSL::SSL
        Threads::Threads
	  PUBLIC
		wampcc_json_static)

  add_dependencies(wampcc_static wampcc_json_static)

  list(APPEND TO_INSTALL wampcc_static)
endif()

##
## Shared library
##
if(BUILD_SHARED_LIBS)
  add_library(wampcc_shared SHARED
      ${LIB_WAMPCC_SRC_FILES}
      ${LIB_3RDPTY_HTTPPARSER_SRC_FILES}
      ${LIB_3RDPTY_APACH_SRC_FILES})

  # Set library output name
  set_target_properties(wampcc_shared PROPERTIES OUTPUT_NAME wampcc)

  # Set library API version
  set_property(TARGET wampcc_shared PROPERTY VERSION "6.0.0")
  set_property(TARGET wampcc_shared PROPERTY SOVERSION 6 )

  target_include_directories(wampcc_shared
    PUBLIC
      $<INSTALL_INTERFACE:include>
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

	target_link_libraries(wampcc_shared
      PRIVATE
	    LibUV::LibUV
	    OpenSSL::SSL
        Threads::Threads
	  PUBLIC
		wampcc_json_shared)
  add_dependencies(wampcc_shared wampcc_json_shared)

  list(APPEND TO_INSTALL wampcc_shared)
endif()

##
## Install targets
##
install(TARGETS ${TO_INSTALL}
    EXPORT wampccExportTargets
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT lib
    BUNDLE  DESTINATION "${INSTALL_BIN_DIR}" COMPONENT lib
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}" COMPONENT lib
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT lib)

install(FILES ${INSTALL_HDRS}
  DESTINATION "${INSTALL_INC_DIR}/wampcc"
  COMPONENT dev)

foreach(t ${TO_INSTALL})
  add_library(wampcc::${t} ALIAS ${t})
endforeach()

# source files
file(GLOB LIB_WAMPCC_JSON_SRC_FILES ${PROJECT_SOURCE_DIR}/libs/json/*.cc)

# list of headers file to install
set(INSTALL_HDRS
  ${PROJECT_SOURCE_DIR}/include/wampcc/json.h
  ${PROJECT_SOURCE_DIR}/include/wampcc/json_internals.h)

##
## Static library
##
if(BUILD_STATIC_LIBS)
  add_library(wampcc_json_static STATIC ${LIB_WAMPCC_JSON_SRC_FILES})

  # Use C++11 standard
  set_property(TARGET wampcc_json_static PROPERTY CXX_STANDARD 11)
  set_property(TARGET wampcc_json_static PROPERTY CXX_STANDARD_REQUIRED ON)

  set_target_properties(wampcc_json_static PROPERTIES OUTPUT_NAME wampcc_json)
  target_include_directories(wampcc_json_static
                             PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/msgpack-c/include)

  target_link_libraries(wampcc_json_static
	PRIVATE
      jansson
      OpenSSL::SSL
	  LibUV::LibUV)

  list(APPEND TO_INSTALL wampcc_json_static)
endif()

##
## Shared library
##
if(BUILD_SHARED_LIBS)
  add_library(wampcc_json_shared SHARED ${LIB_WAMPCC_JSON_SRC_FILES})

  # Use C++11 standard
  set_property(TARGET wampcc_json_shared PROPERTY CXX_STANDARD 11)
  set_property(TARGET wampcc_json_shared PROPERTY CXX_STANDARD_REQUIRED ON)

  # Set library output name
  set_target_properties(wampcc_json_shared PROPERTIES OUTPUT_NAME wampcc_json)

  # Set library API version
  set_property(TARGET wampcc_json_shared PROPERTY VERSION "6.0.0")
  set_property(TARGET wampcc_json_shared PROPERTY SOVERSION 6 )

  target_include_directories(wampcc_json_shared
    PRIVATE
	  ${PROJECT_SOURCE_DIR}/3rdparty/msgpack-c/include)

  target_link_libraries(wampcc_json_shared
	PRIVATE
      jansson
      OpenSSL::SSL
	  LibUV::LibUV)

  list(APPEND TO_INSTALL wampcc_json_shared)

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

project(tps_module CXX)

set(TPS_PRIVATE_INCLUDE_DIRS
    ${TPS_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
    ${APR_INCLUDE_DIRS}
    ${SVRCORE_INCLUDE_DIRS}
    ${MOZLDAP_INCLUDE_DIRS}
)

set(TPS_MODULE
    tps_module
    CACHE INTERNAL "tps apache module"
)

set(TPS_LINK_LIBRARIES
    ${TPS_SHARED_LIBRARY}
    ${NSPR_LIBRARIES}
    ${NSS_LIBRARIES}
    ${APR_LIBRARIES}
    ${SVRCORE_LIBRARIES}
    ${MOZLDAP_LIBRARIES}
    ${TOKENDB_SHARED_LIBRARY}
    ${TPS_SHARED_LIBRARY}
)

set(tps_module_SRCS
    AP_Context.cpp
    AP_Session.cpp
    mod_tps.cpp
)

include_directories(${TPS_PRIVATE_INCLUDE_DIRS})

add_library(${TPS_MODULE} MODULE ${tps_module_SRCS})
target_link_libraries(${TPS_MODULE} ${TPS_LINK_LIBRARIES})

set_target_properties(${TPS_MODULE}
    PROPERTIES
        OUTPUT_NAME
            mod_tps
        PREFIX ""
)

install(
    TARGETS
        ${TPS_MODULE}
    DESTINATION
        ${LIB_INSTALL_DIR}/httpd/modules
)

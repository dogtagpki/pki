project(tokendb_module CXX)

set(TOKENDB_PRIVATE_INCLUDE_DIRS
    ${TOKENDB_PUBLIC_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
    ${APR_INCLUDE_DIRS}
    ${SVRCORE_INCLUDE_DIRS}
    ${LDAP_INCLUDE_DIRS}
)

set(TOKENDB_MODULE
    tokendb_module
    CACHE INTERNAL "tokendb apache module"
)

set(TOKENDB_LINK_LIBRARIES
    ${TOKENDB_SHARED_LIBRARY}
    ${NSPR_LIBRARIES}
    ${NSS_LIBRARIES}
    ${APR_LIBRARIES}
    ${SVRCORE_LIBRARIES}
    ${LDAP_LIBRARIES}
)

set(tokendb_module_SRCS
    mod_tokendb.cpp
)

include_directories(${TOKENDB_PRIVATE_INCLUDE_DIRS})

add_library(${TOKENDB_MODULE} MODULE ${tokendb_module_SRCS})
add_dependencies(${TOKENDB_MODULE} pki-tps-jar)
target_link_libraries(${TOKENDB_MODULE} ${TOKENDB_LINK_LIBRARIES})

set_target_properties(${TOKENDB_MODULE}
    PROPERTIES
        OUTPUT_NAME
            mod_tokendb
        PREFIX ""
)

install(
    TARGETS
        ${TOKENDB_MODULE}
    DESTINATION
        ${LIB_INSTALL_DIR}/httpd/modules
)

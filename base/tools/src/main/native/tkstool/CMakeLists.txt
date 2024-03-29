project(tkstool C)

set(TKSTOOL_PRIVATE_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(TKSTOOL_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(tkstool_SRCS
    delete.c
    file.c
    find.c
    help.c
    key.c
    list.c
    modules.c
    pppolicy.c
    random.c
    retrieve.c
    secerror.c
    secpwd.c
    secutil.c
    tkstool.c
    util.c
    version.c
)

include_directories(${TKSTOOL_PRIVATE_INCLUDE_DIRS})

add_executable(tkstool EXCLUDE_FROM_ALL ${tkstool_SRCS})
add_dependencies(native tkstool)
target_link_libraries(tkstool ${TKSTOOL_LINK_LIBRARIES})

install(
    TARGETS tkstool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

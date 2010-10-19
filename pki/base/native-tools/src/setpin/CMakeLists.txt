project(setpin C)

find_package(MozLDAP REQUIRED)

set(SETPIN_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
  ${MOZLDAP_INCLUDE_DIRS}
)

set(SETPIN_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
  ${MOZLDAP_LIBRARIES}
)

set(setpin_SRCS
    b64.c
    options.c
    setpin.c
    setpin_options.c
)

include_directories(${SETPIN_PRIVATE_INCLUDE_DIRS})

add_executable(setpin ${setpin_SRCS})

target_link_libraries(setpin ${SETPIN_LINK_LIBRARIES})

install(
    TARGETS setpin
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

install(
    FILES
        setpin.conf
    DESTINATION
        ${LIB_INSTALL_DIR}/pki/native-tools/
)

project(pistool C)

set(PISTOOL_PUBLIC_INCLUDE_DIRS
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PISTOOL_INCLUDE_DIR}
  CACHE INTERNAL "pistool public include directories"
)

set(PISTOOL_PRIVATE_INCLUDE_DIRS
  ${PISTOOL_PUBLIC_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

find_library(SOFTOKN3_LIBRARY
  NAMES
    softokn3
  PATHS
    ${_NSS_LIBDIR}
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
)

if (SOFTOKN3_LIBRARY)
  set(FIPS_LIBRARIES
      ${SOFTOKN3_LIBRARY}
  )
endif (SOFTOKN3_LIBRARY)

set(PISTOOL_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
  ${FIPS_LIBRARIES}
)

add_definitions(-DXP_UNIX)

# For now, create the executable without resolving warnings
add_definitions(-Wall)
add_definitions(-Wno-error)

# FILE(GLOB pistool_SRCS "*.c")

set(pistool_SRCS
    delete.c
    file.c
    find.c
    help.c
    key.c
    list.c
    modules.c
    pistool.c
    pppolicy.c
    random.c
    retrieve.c
    secerror.c
    secpwd.c
    secutil.c
    util.c
    version.c
)

include_directories(${PISTOOL_PRIVATE_INCLUDE_DIRS})

add_executable(pistool EXCLUDE_FROM_ALL ${pistool_SRCS})
add_dependencies(native pistool)
target_link_libraries(pistool ${PISTOOL_LINK_LIBRARIES})

install(
    TARGETS pistool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

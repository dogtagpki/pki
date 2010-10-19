project(osutil_library C)

set(OSUTIL_PUBLIC_INCLUDE_DIRS
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  CACHE INTERNAL "osutil public include directories"
)

set(OSUTIL_PRIVATE_INCLUDE_DIRS
  ${OSUTIL_PUBLIC_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${JNI_INCLUDE_DIRS}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(OSUTIL_SHARED_LIBRARY
  osutil_library
  CACHE INTERNAL "osutil shared library"
)

set(OSUTIL_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
  ${JNI_LIBRARIES}
)

set(osutil_library_HDRS
    LIBC.h
    ResourceLimit.h
    Signal.h
    UserID.h
    OSUtil.h
)

set(osutil_library_SRCS
    LibC.c
    OSUtil.c
    ResourceLimit.c
    Signal.c
    UserID.c
)

include_directories(${OSUTIL_PRIVATE_INCLUDE_DIRS})

add_custom_command(
    OUTPUT
        ${osutil_library_HDRS}
    COMMAND
        ${JAVA_HEADER}
            -classpath ${OSUTIL_JAVA_OBJECT_DIR}
            -jni -d ${CMAKE_CURRENT_BINARY_DIR}
            com.netscape.osutil.LibC
            com.netscape.osutil.ResourceLimit
            com.netscape.osutil.Signal
            com.netscape.osutil.UserID
            com.netscape.osutil.OSUtil
)

add_library(${OSUTIL_SHARED_LIBRARY} SHARED ${osutil_library_HDRS} ${osutil_library_SRCS})
target_link_libraries(${OSUTIL_SHARED_LIBRARY} ${OSUTIL_LINK_LIBRARIES})
add_dependencies(${OSUTIL_SHARED_LIBRARY} osutil)

set_target_properties(${OSUTIL_SHARED_LIBRARY}
    PROPERTIES
        VERSION
            ${OSUTIL_LIBRARY_VERSION}
        SOVERSION
            ${OSUTIL_LIBRARY_SOVERSION}
        OUTPUT_NAME
            osutil
)

install(
    TARGETS
        ${OSUTIL_SHARED_LIBRARY}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
)

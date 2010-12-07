project(symkey_library CXX)

set(SYMKEY_PUBLIC_INCLUDE_DIRS
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  CACHE INTERNAL "symkey public include directories"
)

set(SYMKEY_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${JNI_INCLUDE_DIRS}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(SYMKEY_SHARED_LIBRARY
  symkey_library
  CACHE INTERNAL "symkey shared library"
)

set(SYMKEY_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(symkey_library_HDRS
    SessionKey.h
)

set(symkey_library_SRCS
    Buffer.cpp
    EncryptData.cpp
    SessionKey.cpp
    SymKey.cpp
)

include_directories(${SYMKEY_PRIVATE_INCLUDE_DIRS})

add_custom_command(
    OUTPUT
        ${symkey_library_HDRS}
    COMMAND
        ${JAVA_HEADER}
            -classpath ${SYMKEY_JAVA_OBJECT_DIR}:/usr/lib/java/jss4.jar
            -jni -d ${CMAKE_CURRENT_BINARY_DIR}
            com.netscape.symkey.SessionKey
)

add_library(${SYMKEY_SHARED_LIBRARY} SHARED ${symkey_library_HDRS} ${symkey_library_SRCS})
target_link_libraries(${SYMKEY_SHARED_LIBRARY} ${SYMKEY_LINK_LIBRARIES})
add_dependencies(${SYMKEY_SHARED_LIBRARY} symkey)

set_target_properties(${SYMKEY_SHARED_LIBRARY}
    PROPERTIES
        VERSION
            ${SYMKEY_LIBRARY_VERSION}
        SOVERSION
            ${SYMKEY_LIBRARY_SOVERSION}
        OUTPUT_NAME
            symkey
)

install(
    TARGETS
        ${SYMKEY_SHARED_LIBRARY}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}/symkey
)

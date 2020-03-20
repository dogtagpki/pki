project(symkey)

javac(symkey-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JSS_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

jar(symkey-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
    DESTINATION
        ${JAVA_LIB_INSTALL_DIR}
)

set(SYMKEY_JAR ${CMAKE_BINARY_DIR}/dist/symkey.jar CACHE INTERNAL "symkey jar file")

set(SYMKEY_PUBLIC_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/src/main/java/com/netscape/symkey
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/java/com/netscape/symkey
    CACHE INTERNAL "symkey public include directories"
)

set(SYMKEY_PRIVATE_INCLUDE_DIRS
    ${CMAKE_BINARY_DIR}
    ${JNI_INCLUDE_DIRS}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
)

set(SYMKEY_SHARED_LIBRARY symkey_library CACHE INTERNAL "symkey shared library")

set(SYMKEY_LINK_LIBRARIES
    ${NSPR_LIBRARIES}
    ${NSS_LIBRARIES}
)

set(symkey_library_HDRS
    src/main/java/com/netscape/symkey/SessionKey.h
)

set(symkey_library_SRCS
    src/main/java/com/netscape/symkey/Buffer.cpp
    src/main/java/com/netscape/symkey/EncryptData.cpp
    src/main/java/com/netscape/symkey/SessionKey.cpp
    src/main/java/com/netscape/symkey/SymKey.cpp
    src/main/java/com/netscape/symkey/NistSP800_108KDF.cpp
)

include_directories(${SYMKEY_PRIVATE_INCLUDE_DIRS})

add_custom_command(
    OUTPUT
        ${symkey_library_HDRS}
    COMMAND
        ${Java_JAVAC_EXECUTABLE}
            -classpath ${CMAKE_CURRENT_BINARY_DIR}/classes:${JAVA_LIB_INSTALL_DIR}/jss4.jar
            -h ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/main/java/com/netscape/symkey/SessionKey.java
)

add_library(${SYMKEY_SHARED_LIBRARY} SHARED
    ${symkey_library_HDRS}
    ${symkey_library_SRCS})

target_link_libraries(${SYMKEY_SHARED_LIBRARY} ${SYMKEY_LINK_LIBRARIES})
add_dependencies(${SYMKEY_SHARED_LIBRARY} symkey-jar)

set_target_properties(${SYMKEY_SHARED_LIBRARY}
    PROPERTIES
        OUTPUT_NAME
            symkey
)

install(
    TARGETS
        ${SYMKEY_SHARED_LIBRARY}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}/symkey
)

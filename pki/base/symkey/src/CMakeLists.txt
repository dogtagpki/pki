project(symkey Java)

set(SYMKEY_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${PROJECT_NAME}.dir/" PARENT_SCOPE)
set(SYMKEY_JAR "${CMAKE_CURRENT_BINARY_DIR}/symkey.jar" CACHE INTERNAL "symkey jar file")

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
    /usr/lib/java
    /usr/share/java
)

set(symkey_java_SRCS
    com/netscape/symkey/SessionKey.java
)

set(CMAKE_JAVA_INCLUDE_PATH ${JSS_JAR})

add_jar(symkey ${symkey_java_SRCS})

install(
    FILES
        ${SYMKEY_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

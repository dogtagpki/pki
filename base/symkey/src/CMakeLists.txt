project(symkey Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
    ${JAVA_LIB_INSTALL_DIR}
    /usr/share/java
)

# build symkey
javac(symkey-classes
    SOURCES
        com/netscape/symkey/*.java
    CLASSPATH
        ${JSS_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
)

jar(symkey-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/symkey-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/symkey/*.class
    DEPENDS
        symkey-classes
)

link(symkey
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
    DEST
        symkey-${APPLICATION_VERSION}.jar
    DEPENDS
        symkey-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
        ${CMAKE_BINARY_DIR}/dist/symkey-${APPLICATION_VERSION}.jar
    DESTINATION
        ${LIB_INSTALL_DIR}/symkey
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
    DESTINATION
        ${JAVA_LIB_INSTALL_DIR}
)

set(SYMKEY_JAR ${CMAKE_BINARY_DIR}/dist/symkey.jar CACHE INTERNAL "symkey jar file")

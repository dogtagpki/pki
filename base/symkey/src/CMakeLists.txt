project(symkey NONE)

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
        ${CMAKE_BINARY_DIR}/dist/symkey.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/symkey/*.class
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

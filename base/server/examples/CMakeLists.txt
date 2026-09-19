project(pki-server-examples)

javac(pki-server-examples-classes
    SOURCES
        java/*.java
    CLASSPATH
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-server-examples-classes)

install(
    DIRECTORY
        java
    DESTINATION
        ${DATA_INSTALL_DIR}/server/examples
)

project(examples)

javac(pki-examples-classes
    SOURCES
        java/*.java
    CLASSPATH
        ${JAXB_API_JAR}
        ${JACKSON2_ANNOTATIONS_JAR}
        ${JSS_JAR}
        ${PKI_COMMON_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-jar
)

add_dependencies(java pki-examples-classes)

install(
    DIRECTORY
        java
    DESTINATION
        ${DATA_INSTALL_DIR}/examples
)

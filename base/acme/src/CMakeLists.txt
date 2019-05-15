project(pki-acme_java NONE)

javac(pki-acme-classes
    SOURCES
        *.java
    CLASSPATH
        ${JAXRS_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-acme.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-acme.mf
)

jar(pki-acme-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-acme.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-acme.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-acme-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-acme.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_ACME_JAR ${CMAKE_BINARY_DIR}/dist/pki-acme.jar CACHE INTERNAL "pki-acme jar file")

project(pki-tomcat7)

# build pki-tomcat
javac(pki-tomcat7-classes
    SOURCES
        *.java
    CLASSPATH
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_SCAN_JAR}
        ${JAXRS_API_JAR}
        ${CMAKE_BINARY_DIR}/../../tomcat
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/../../tomcat
    DEPENDS
        pki-tomcat-classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-tomcat.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-tomcat.mf
)

jar(pki-tomcat-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-tomcat.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/../../tomcat
    DEPENDS
        pki-tomcat-classes
        pki-tomcat7-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TOMCAT_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar CACHE INTERNAL "pki-tomcat jar file")

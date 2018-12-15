project(pki-tomcat-7.0)

# build pki-tomcat
javac(pki-tomcat-classes
    SOURCES
        ../../tomcat/src/*.java
        *.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${APACHE_COMMONS_LANG_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_SCAN_JAR}
        ${SLF4J_API_JAR}
        ${JSS_JAR} ${TOMCATJSS_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/../../tomcat
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-tools-jar
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
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TOMCAT_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar CACHE INTERNAL "pki-tomcat jar file")

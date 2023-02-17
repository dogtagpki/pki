project(pki-tomcat-9.0)

# build pki-tomcat
javac(pki-tomcat-classes
    SOURCES
        ../tomcat/src/main/java/*.java
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${JASPIC_API_JAR}
        ${COMMONS_LANG3_JAR}
        ${TOMCAT_API_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_COYOTE_JAR} ${TOMCAT_UTIL_SCAN_JAR}
        ${SLF4J_API_JAR}
        ${JSS_JAR} ${TOMCATJSS_JAR}
        ${PKI_COMMON_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/../tomcat
    DEPENDS
        pki-common-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

set(PKI_TOMCAT_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar CACHE INTERNAL "pki-tomcat jar file")

jar(pki-tomcat-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/../tomcat
    DEPENDS
        pki-tomcat-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

install(
    DIRECTORY
        conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/conf/
)

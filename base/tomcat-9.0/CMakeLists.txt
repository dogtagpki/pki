project(pki-tomcat-9.0)

javac(pki-tomcat-9.0-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${JASPIC_API_JAR}
        ${COMMONS_LANG3_JAR}
        ${TOMCAT_API_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_COYOTE_JAR} ${TOMCAT_UTIL_SCAN_JAR}
        ${SLF4J_API_JAR}
        ${JSS_JAR}
        ${JSS_TOMCAT_JAR}
        ${JSS_TOMCAT_9_0_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_TOMCAT_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tomcat-jar
)

add_dependencies(java pki-tomcat-9.0-classes)

set(PKI_TOMCAT_9_0_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat-9.0.jar
    CACHE INTERNAL "pki-tomcat-9.0.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-tomcat-9.0-jar
    CREATE
        ${PKI_TOMCAT_9_0_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tomcat-9.0-classes
)

add_dependencies(java pki-tomcat-9.0-jar)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_TOMCAT_9_0_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

install(
    DIRECTORY
        conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/conf/
)

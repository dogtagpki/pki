project(pki-tomcat)

javac(pki-tomcat-classes
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
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-jar
)

add_dependencies(java pki-tomcat-classes)

set(PKI_TOMCAT_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    CACHE INTERNAL "pki-tomcat.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-tomcat-jar
    CREATE
        ${PKI_TOMCAT_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tomcat-classes
)

add_dependencies(java pki-tomcat-jar)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_TOMCAT_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

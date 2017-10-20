project(base)

find_file(SERVLET_JAR
    NAMES
        servlet.jar
    PATHS
        /usr/share/java
)

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
        jboss-jaxrs-2.0-api.jar
    PATHS
        ${RESTEASY_LIB}
        /usr/share/java
)

find_file(SLF4J_API_JAR
    NAMES
        slf4j-api.jar
    PATHS
        /usr/share/java/slf4j
)

find_file(SLF4J_JDK14_JAR
    NAMES
        slf4j-jdk14.jar
    PATHS
        /usr/share/java/slf4j
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_HTTPCLIENT_JAR
    NAMES
        commons-httpclient.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_IO_JAR
    NAMES
        commons-io.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_LANG_JAR
    NAMES
        commons-lang.jar
    PATHS
        /usr/share/java
)

find_file(HAMCREST_JAR
    NAMES
        core.jar
    PATHS
        /usr/share/java/hamcrest
)

find_file(HTTPCLIENT_JAR
    NAMES
        httpclient.jar
    PATHS
        /usr/share/java/httpcomponents
)

find_file(HTTPCORE_JAR
    NAMES
        httpcore.jar
    PATHS
        /usr/share/java/httpcomponents
)

find_file(JACKSON_CORE_JAR
    NAMES
        jackson-core-asl.jar
    PATHS
        /usr/share/java/jackson
)

find_file(JACKSON_MAPPER_JAR
    NAMES
        jackson-mapper-asl.jar
    PATHS
        /usr/share/java/jackson
)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(JUNIT_JAR
    NAMES
        junit.jar
    PATHS
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(NUXWDOG_JAR
    NAMES
        nuxwdog.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(TOMCAT_API_JAR
    NAMES
        tomcat-api.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(TOMCAT_CATALINA_JAR
    NAMES
        catalina.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(TOMCAT_UTIL_JAR
    NAMES
        tomcat-util.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(TOMCAT_UTIL_SCAN_JAR
    NAMES
        tomcat-util-scan.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(TOMCATJSS_JAR
    NAMES
        tomcatjss.jar
    PATHS
        /usr/share/java
)

find_file(VELOCITY_JAR
    NAMES
        velocity.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

# The order is important!
if (APPLICATION_FLAVOR_PKI_CORE)

    add_subdirectory(test)
    add_subdirectory(symkey)
    add_subdirectory(util)
    add_subdirectory(common)
    add_subdirectory(native-tools)
    add_subdirectory(java-tools)

    if(WITH_SERVER)
        add_subdirectory(server)
        add_subdirectory(ca)
        add_subdirectory(kra)
        add_subdirectory(ocsp)
        add_subdirectory(tks)
        add_subdirectory(tps)
        # required for native 'tpsclient' utility
        add_subdirectory(tps-client)

        if(WITH_JAVADOC)
            add_subdirectory(javadoc)
        endif(WITH_JAVADOC)

    endif(WITH_SERVER)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/VERSION
        ${CMAKE_CURRENT_BINARY_DIR}/VERSION
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/VERSION
        DESTINATION
            ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}
    )

endif (APPLICATION_FLAVOR_PKI_CORE)

if (APPLICATION_FLAVOR_PKI_CONSOLE)
    add_subdirectory(test)
    add_subdirectory(console)
endif (APPLICATION_FLAVOR_PKI_CONSOLE)

project(base)

find_file(SERVLET_JAR
    NAMES
        servlet.jar
        servlet-api-3.1.jar
    PATHS
        /usr/share/java
)

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
        jboss-jaxrs-2.0-api.jar
        javax.ws.rs-api.jar
    PATHS
        /usr/share/java
)

find_file(SLF4J_API_JAR
    NAMES
        slf4j-api.jar
    PATHS
        /usr/share/java/slf4j
        /usr/share/java
)

find_file(SLF4J_JDK14_JAR
    NAMES
        slf4j-jdk14.jar
    PATHS
        /usr/share/java/slf4j
        /usr/share/java
)

find_file(SLF4J_SIMPLE_JAR
    NAMES
        slf4j-simple.jar
    PATHS
        /usr/share/java/slf4j
        /usr/share/java
)

find_file(COMMONS_CLI_JAR
    NAMES
        commons-cli.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_IO_JAR
    NAMES
        commons-io.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_LANG3_JAR
    NAMES
        commons-lang3.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_LOGGING_JAR
    NAMES
        commons-logging.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_NET_JAR
    NAMES
        commons-net.jar
    PATHS
        /usr/share/java
)

find_file(HAMCREST_JAR
    NAMES
        core.jar hamcrest.jar
    PATHS
        /usr/share/java/hamcrest
)

find_file(HTTPCLIENT_JAR
    NAMES
        httpclient.jar
    PATHS
        /usr/share/java/httpcomponents
        /usr/share/java
)

find_file(HTTPCORE_JAR
    NAMES
        httpcore.jar
    PATHS
        /usr/share/java/httpcomponents
        /usr/share/java
)

find_file(JACKSON2_CORE_JAR
    NAMES
        jackson-core.jar
    PATHS
        /usr/share/java
)

find_file(JACKSON2_DATABIND_JAR
    NAMES
        jackson-databind.jar
    PATHS
        /usr/share/java
)

find_file(JACKSON2_ANNOTATIONS_JAR
    NAMES
        jackson-annotations.jar
    PATHS
        /usr/share/java
)

find_file(JACKSON2_JAXRS_BASE_JAR
    NAMES
        jackson-jaxrs-base.jar
    PATHS
        /usr/share/java/jackson-jaxrs-providers
        /usr/share/java
)

find_file(JACKSON2_JAXRS_JSON_PROVIDER_JAR
    NAMES
        jackson-jaxrs-json-provider.jar
    PATHS
        /usr/share/java/jackson-jaxrs-providers
        /usr/share/java
)

find_file(JACKSON2_JAXB_ANNOTATIONS_JAR
    NAMES
        jackson-module-jaxb-annotations.jar
    PATHS
        /usr/share/java/jackson-modules
        /usr/share/java
)

execute_process(
    COMMAND awk -F= "$1==\"ID\" { print $2 ;}" /etc/os-release
    OUTPUT_VARIABLE DISTRO
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

find_program(XMVN_RESOLVE /bin/xmvn-resolve)

if(XMVN_RESOLVE)
    execute_process(
        COMMAND xmvn-resolve jakarta.xml.bind:jakarta.xml.bind-api:4
        OUTPUT_VARIABLE JAXB_API_JAR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    find_file(JAXB_API_JAR
        NAMES
            jaxb-api.jar
        PATHS
            /usr/share/java
    )
endif(XMVN_RESOLVE)

if(XMVN_RESOLVE)
    execute_process(
        COMMAND xmvn-resolve jakarta.activation:jakarta.activation-api:2
        OUTPUT_VARIABLE JAVAX_ACTIVATION_JAR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    find_file(JAVAX_ACTIVATION_JAR
        NAMES
            jakarta.activation.jar
            jakarta-activation.jar
            javax.activation.jar
            javax-activation.jar
        PATHS
            /usr/share/java/jakarta-activation
            /usr/share/java/jakarta
            /usr/share/java/javax-activation
            /usr/share/java/javax
            /usr/share/java
    )
endif(XMVN_RESOLVE)

find_file(JAVAX_ANNOTATIONS_API_JAR
    NAMES
        jakarta.annotation-api.jar
        jboss-annotations-api_1.2_spec.jar
    PATHS
        /usr/share/java/jakarta-annotations
        /usr/share/java/jboss-annotations-1.2-api
        /usr/share/java
)

find_file(JBOSS_LOGGING_JAR
    NAMES
        jboss-logging.jar
    PATHS
        /usr/share/java/jboss-logging
        /usr/share/java
)

find_file(JSS_JAR
    NAMES
        jss.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(JUNIT_JUPITER_API_JAR
    NAMES
        junit-jupiter-api.jar
    PATHS
        /usr/share/java/junit5
)

find_file(JUNIT_JUPITER_ENGINE_JAR
    NAMES
        junit-jupiter-engine.jar
    PATHS
        /usr/share/java/junit5
)

find_file(JUNIT_PLATFORM_COMMONS_JAR
    NAMES
        junit-platform-commons.jar
    PATHS
        /usr/share/java/junit5
)

find_file(JUNIT_PLATFORM_ENGINE_JAR
    NAMES
        junit-platform-engine.jar
    PATHS
        /usr/share/java/junit5
)

find_file(JUNIT_PLATFORM_LAUNCHER_JAR
    NAMES
        junit-platform-launcher.jar
    PATHS
        /usr/share/java/junit5
)

find_file(JUNIT_PLATFORM_SUITE_JAR
    NAMES
        junit-platform-suite-api.jar
    PATHS
        /usr/share/java/junit5
)

find_file(OPENTEST4J_JAR
    NAMES
        opentest4j.jar
    PATHS
        /usr/share/java/opentest4j
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_CLIENT_JAR
    NAMES
        resteasy-client.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_JACKSON2_PROVIDER_JAR
    NAMES
        resteasy-jackson2-provider.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_SERVLET_INITIALIZER_JAR
    NAMES
        resteasy-servlet-initializer.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(JASPIC_API_JAR
    NAMES
        jaspic-api.jar
        tomcat9-jaspic-api.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_API_JAR
    NAMES
        tomcat-api.jar
        tomcat9-api.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_CATALINA_JAR
    NAMES
        catalina.jar
        tomcat9-catalina.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_COYOTE_JAR
    NAMES
        tomcat-coyote.jar
        tomcat9-coyote.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_UTIL_JAR
    NAMES
        tomcat-util.jar
        tomcat9-util.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_UTIL_SCAN_JAR
    NAMES
        tomcat-util-scan.jar
        tomcat9-util-scan.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(JSS_TOMCAT_JAR
    NAMES
        jss-tomcat.jar
    PATHS
        /usr/share/java/jss
)

find_file(JSS_TOMCAT_9_0_JAR
    NAMES
        jss-tomcat-9.0.jar
    PATHS
        /usr/share/java/jss
)

find_file(IDM_CONSOLE_FRAMEWORK_JAR
    NAMES
        idm-console-framework.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

add_subdirectory(common)
add_subdirectory(tools)

if(WITH_SERVER OR WITH_CA OR WITH_KRA OR WITH_OCSP OR WITH_TKS OR WITH_TPS OR WITH_ACME OR WITH_EST)

    add_subdirectory(tomcat)
    add_subdirectory(${APP_SERVER})
    add_subdirectory(server)
    add_subdirectory(server-webapp)

    list(APPEND PKI_JAVADOC_SOURCEPATH
        ${CMAKE_SOURCE_DIR}/base/server/src/main/java)

    list(APPEND PKI_JAVADOC_SUBPACKAGES
        com.netscape.cms)

    list(APPEND PKI_JAVADOC_CLASSPATH
        ${PKI_TOMCAT_JAR}
        ${PKI_TOMCAT_9_0_JAR}
        ${PKI_SERVER_JAR})

    if(WITH_CA)
        add_subdirectory(ca)
    endif(WITH_CA)

    if(WITH_KRA)
        add_subdirectory(kra)
    endif(WITH_KRA)

    if(WITH_OCSP)
        add_subdirectory(ocsp)
    endif(WITH_OCSP)

    if(WITH_TKS)
        add_subdirectory(tks)
    endif(WITH_TKS)

    if(WITH_TPS)
        add_subdirectory(tps)
    endif(WITH_TPS)

    if(WITH_ACME)
        add_subdirectory(acme)
    endif(WITH_ACME)

    if(WITH_EST)
        add_subdirectory(est)
    endif(WITH_EST)

endif(WITH_SERVER OR WITH_CA OR WITH_KRA OR WITH_OCSP OR WITH_TKS OR WITH_TPS OR WITH_ACME OR WITH_EST)

if(WITH_JAVADOC)
    add_subdirectory(javadoc)
endif(WITH_JAVADOC)

if(WITH_CONSOLE)
    add_subdirectory(console)
endif(WITH_CONSOLE)

if(WITH_META)
    add_subdirectory(meta)
endif(WITH_META)

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

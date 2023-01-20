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
    COMMAND xmvn-resolve jakarta.xml.bind:jakarta.xml.bind-api
    OUTPUT_VARIABLE JAXB_API_JAR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND xmvn-resolve jakarta.activation:jakarta.activation-api
    OUTPUT_VARIABLE JAVAX_ACTIVATION_JAR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

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

find_file(JSS_SYMKEY_JAR
    NAMES
        jss-symkey.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(JUNIT_JAR
    NAMES
        junit.jar
        junit4.jar
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

find_file(TOMCATJSS_JAR
    NAMES
        tomcatjss.jar
    PATHS
        /usr/share/java
)

find_file(BASE_JAR
    NAMES
        idm-console-base.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(MMC_JAR
    NAMES
        idm-console-mcc.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(MMC_EN_JAR
    NAMES
        idm-console-mcc_en.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(NMCLF_JAR
    NAMES
        idm-console-nmclf.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(NMCLF_EN_JAR
    NAMES
        idm-console-nmclf_en.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

add_subdirectory(common)
add_subdirectory(tools)

if(WITH_SERVER OR WITH_CA OR WITH_KRA OR WITH_OCSP OR WITH_TKS OR WITH_TPS OR WITH_ACME OR WITH_EST)

    add_subdirectory(${APP_SERVER})
    add_subdirectory(server)

    list(APPEND PKI_JAVADOC_SOURCEPATH
        ${CMAKE_SOURCE_DIR}/base/server/src/main/java)

    list(APPEND PKI_JAVADOC_SUBPACKAGES
        com.netscape.cms)

    list(APPEND PKI_JAVADOC_CLASSPATH
        ${PKI_TOMCAT_JAR}
        ${PKI_CMS_JAR})

    list(APPEND PKI_JAVADOC_DEPENDS
        pki-tomcat-jar
        pki-cms-jar)

    if(WITH_CA)
        add_subdirectory(ca)
        list(APPEND PKI_JAVADOC_DEPENDS pki-ca-jar)
    endif(WITH_CA)

    if(WITH_KRA)
        add_subdirectory(kra)
        list(APPEND PKI_JAVADOC_DEPENDS pki-kra-jar)
    endif(WITH_KRA)

    if(WITH_OCSP)
        add_subdirectory(ocsp)
        list(APPEND PKI_JAVADOC_DEPENDS pki-ocsp-jar)
    endif(WITH_OCSP)

    if(WITH_TKS)
        add_subdirectory(tks)
        list(APPEND PKI_JAVADOC_DEPENDS pki-tks-jar)
    endif(WITH_TKS)

    if(WITH_TPS)
        add_subdirectory(tps)
        list(APPEND PKI_JAVADOC_DEPENDS pki-tps-jar)
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

if (WITH_CONSOLE)
    add_subdirectory(console)
endif (WITH_CONSOLE)

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

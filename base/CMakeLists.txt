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
        ${RESTEASY_LIB}
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

find_file(COMMONS_COLLECTIONS_JAR
    NAMES
        commons-collections.jar
        commons-collections3.jar
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
        core.jar
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

find_file(JAXB_API_JAR
    NAMES
        jaxb-api.jar
    PATHS
        /usr/share/java
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
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_CLIENT_JAR
    NAMES
        resteasy-client.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(SYMKEY_JAR
    NAMES
        symkey.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)

find_file(JASPIC_API_JAR
    NAMES
        jaspic-api.jar
        tomcat8-jaspic-api.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_API_JAR
    NAMES
        tomcat-api.jar
        tomcat8-api.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_CATALINA_JAR
    NAMES
        catalina.jar
        tomcat8-catalina.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_COYOTE_JAR
    NAMES
        tomcat-coyote.jar
        tomcat8-coyote.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_UTIL_JAR
    NAMES
        tomcat-util.jar
        tomcat8-util.jar
    PATHS
        /usr/share/java/tomcat
        /usr/share/java
)

find_file(TOMCAT_UTIL_SCAN_JAR
    NAMES
        tomcat-util-scan.jar
        tomcat8-util-scan.jar
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
        xalan2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
        xercesImpl.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XML_COMMONS_APIS_JAR
    NAMES
        xml-commons-apis.jar
        xml-apis.jar
    PATHS
        /usr/share/java
)

find_file(XML_COMMONS_RESOLVER_JAR
    NAMES
        xml-commons-resolver.jar
        xml-resolver.jar
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


# The order is important!
if (BUILD_PKI_CORE OR BUILD_PKI_CONSOLE)
    add_subdirectory(test)
    add_subdirectory(symkey)
    add_subdirectory(util)
    add_subdirectory(common)
    add_subdirectory(native-tools)
    add_subdirectory(java-tools)

    if(WITH_SERVER)

        add_subdirectory(server)

        add_subdirectory(acme)
        add_subdirectory(ca)
        add_subdirectory(kra)
        add_subdirectory(ocsp)
        add_subdirectory(tks)
        add_subdirectory(tps)

        # required for native 'tpsclient' utility
        add_subdirectory(tps-client)

        list(APPEND PKI_JAVADOC_SOURCEPATH
            ${CMAKE_SOURCE_DIR}/base/server/src)

        list(APPEND PKI_JAVADOC_SUBPACKAGES
            com.netscape.cms)

        list(APPEND PKI_JAVADOC_CLASSPATH
            ${PKI_TOMCAT_JAR}
            ${PKI_CMS_JAR})

        list(APPEND PKI_JAVADOC_DEPENDS
            pki-tomcat-jar
            pki-cms-jar
            pki-ca-jar
            pki-kra-jar
            pki-ocsp-jar
            pki-tks-jar
            pki-tps-jar)

    endif(WITH_SERVER)

    if(WITH_JAVADOC)
        add_subdirectory(javadoc)
    endif(WITH_JAVADOC)

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

endif (BUILD_PKI_CORE OR BUILD_PKI_CONSOLE)

if (BUILD_PKI_CONSOLE)
    add_subdirectory(console)
endif (BUILD_PKI_CONSOLE)

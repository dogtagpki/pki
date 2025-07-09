project(base)
find_file(SERVLET_JAR
    NAMES
        servlet.jar
        servlet-api-3.1.jar
        tomcat9-servlet-api.jar
        tomcat-servlet-api.jar
    PATHS
        /usr/share/java
)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jboss-jaxrs-api_2.0_spec-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JAXRS_API_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
if (JAXRS_API_VERSION)
    # use imported JARs

    set(JAXRS_API_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jboss-jaxrs-api_2.0_spec-${JAXRS_API_VERSION}.jar")
    set(JAXRS_API_LINK "jboss-jaxrs-api_2.0_spec-${JAXRS_API_VERSION}.jar")

else()
    # use system JARs

    find_file(JAXRS_API_JAR
        NAMES
            jaxrs-api.jar
            jboss-jaxrs-2.0-api.jar
            javax.ws.rs-api.jar
        PATHS
            /usr/share/java
    )
    set(JAXRS_API_LINK "../../../..${JAXRS_API_JAR}")

endif (JAXRS_API_VERSION)

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
        hamcrest.jar hamcrest-core.jar
    PATHS
        /usr/share/java/hamcrest
        /usr/share/java
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

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jackson-annotations-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JACKSON_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (JACKSON_VERSION)
    # use imported JARs

    set(JACKSON_ANNOTATIONS_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-annotations-${JACKSON_VERSION}.jar")
    set(JACKSON_ANNOTATIONS_LINK "jackson-annotations-${JACKSON_VERSION}.jar")

    set(JACKSON_CORE_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-core-${JACKSON_VERSION}.jar")
    set(JACKSON_CORE_LINK "jackson-core-${JACKSON_VERSION}.jar")

    set(JACKSON_DATABIND_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-databind-${JACKSON_VERSION}.jar")
    set(JACKSON_DATABIND_LINK "jackson-databind-${JACKSON_VERSION}.jar")

    set(JACKSON_JAXRS_BASE_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-jaxrs-base-${JACKSON_VERSION}.jar")
    set(JACKSON_JAXRS_BASE_LINK "jackson-jaxrs-base-${JACKSON_VERSION}.jar")

    set(JACKSON_JAXRS_JSON_PROVIDER_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-jaxrs-json-provider-${JACKSON_VERSION}.jar")
    set(JACKSON_JAXRS_JSON_PROVIDER_LINK "jackson-jaxrs-json-provider-${JACKSON_VERSION}.jar")

    set(JACKSON_MODULE_JAXB_ANNOTATIONS_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jackson-module-jaxb-annotations-${JACKSON_VERSION}.jar")
    set(JACKSON_MODULE_JAXB_ANNOTATIONS_LINK "jackson-module-jaxb-annotations-${JACKSON_VERSION}.jar")

else()
    # use system JARs

    find_file(JACKSON_ANNOTATIONS_JAR
        NAMES
            jackson-annotations.jar
        PATHS
            /usr/share/java
    )
    set(JACKSON_ANNOTATIONS_LINK "../../../..${JACKSON_ANNOTATIONS_JAR}")

    find_file(JACKSON_CORE_JAR
        NAMES
            jackson-core.jar
        PATHS
            /usr/share/java
    )
    set(JACKSON_CORE_LINK "../../../..${JACKSON_CORE_JAR}")

    find_file(JACKSON_DATABIND_JAR
        NAMES
            jackson-databind.jar
        PATHS
            /usr/share/java
    )
    set(JACKSON_DATABIND_LINK "../../../..${JACKSON_DATABIND_JAR}")

    find_file(JACKSON_JAXRS_BASE_JAR
        NAMES
            jackson-jaxrs-base.jar
        PATHS
            /usr/share/java/jackson-jaxrs-providers
            /usr/share/java
    )
    set(JACKSON_JAXRS_BASE_LINK "../../../..${JACKSON_JAXRS_BASE_JAR}")

    find_file(JACKSON_JAXRS_JSON_PROVIDER_JAR
        NAMES
            jackson-jaxrs-json-provider.jar
        PATHS
            /usr/share/java/jackson-jaxrs-providers
            /usr/share/java
    )
    set(JACKSON_JAXRS_JSON_PROVIDER_LINK "../../../..${JACKSON_JAXRS_JSON_PROVIDER_JAR}")

    find_file(JACKSON_MODULE_JAXB_ANNOTATIONS_JAR
        NAMES
            jackson-module-jaxb-annotations.jar
        PATHS
            /usr/share/java/jackson-modules
            /usr/share/java
    )
    set(JACKSON_MODULE_JAXB_ANNOTATIONS_LINK "../../../..${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}")

endif (JACKSON_VERSION)

execute_process(
    COMMAND awk -F= "$1==\"ID\" { print $2 ;}" /etc/os-release
    OUTPUT_VARIABLE DISTRO
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

find_program(XMVN_RESOLVE /bin/xmvn-resolve)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jakarta\\.xml\\.bind-api-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JAXB_API_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (JAXB_API_VERSION)
    # use imported JARs

    set(JAXB_API_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jakarta.xml.bind-api-${JAXB_API_VERSION}.jar")
    set(JAXB_API_LINK "jakarta.xml.bind-api-${JAXB_API_VERSION}.jar")

else()
    # use system JARs

    if(XMVN_RESOLVE)
        execute_process(
            COMMAND xmvn-resolve jakarta.xml.bind:jakarta.xml.bind-api:4
            OUTPUT_VARIABLE JAXB_API_JAR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else()
        find_file(JAXB_API_JAR
            NAMES
                jakarta.xml.bind-api.jar
                jaxb-api.jar
            PATHS
                /usr/share/java/jaxb-api4
                /usr/share/java/jaxb-api
                /usr/share/java
        )
    endif(XMVN_RESOLVE)
    set(JAXB_API_LINK "../../../..${JAXB_API_JAR}")

endif (JAXB_API_VERSION)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jakarta\\.activation-api-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JAKARTA_ACTIVATION_API_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (JAKARTA_ACTIVATION_API_VERSION)
    # use imported JARs

    set(JAKARTA_ACTIVATION_API_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jakarta.activation-api-${JAKARTA_ACTIVATION_API_VERSION}.jar")
    set(JAKARTA_ACTIVATION_API_LINK "jakarta.activation-api-${JAKARTA_ACTIVATION_API_VERSION}.jar")

else()
    # use system JARs

    if(XMVN_RESOLVE)
        execute_process(
            COMMAND xmvn-resolve jakarta.activation:jakarta.activation-api:2
            OUTPUT_VARIABLE JAKARTA_ACTIVATION_API_JAR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else()
        find_file(JAKARTA_ACTIVATION_API_JAR
            NAMES
                jakarta.activation-api.jar
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
    set(JAKARTA_ACTIVATION_API_LINK "../../../..${JAKARTA_ACTIVATION_API_JAR}")

endif (JAKARTA_ACTIVATION_API_VERSION)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jakarta\\.annotation-api-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JAKARTA_ANNOTATION_API_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (JAKARTA_ANNOTATION_API_VERSION)
    # use imported JARs

    set(JAKARTA_ANNOTATION_API_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jakarta.annotation-api-${JAKARTA_ANNOTATION_API_VERSION}.jar")
    set(JAKARTA_ANNOTATION_API_LINK "jakarta.annotation-api-${JAKARTA_ANNOTATION_API_VERSION}.jar")

else()
    # use system JARs

    find_file(JAKARTA_ANNOTATION_API_JAR
        NAMES
            jakarta.annotation-api.jar
            jboss-annotations-api_1.2_spec.jar
        PATHS
            /usr/share/java/jakarta-annotations
            /usr/share/java/jboss-annotations-1.2-api
            /usr/share/java
    )
    set(JAKARTA_ANNOTATION_API_LINK "../../../..${JAKARTA_ANNOTATION_API_JAR}")

endif (JAKARTA_ANNOTATION_API_VERSION)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^jboss-logging-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE JBOSS_LOGGING_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (JBOSS_LOGGING_VERSION)
    # use imported JARs

    set(JBOSS_LOGGING_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/jboss-logging-${JBOSS_LOGGING_VERSION}.jar")
    set(JBOSS_LOGGING_LINK "jboss-logging-${JBOSS_LOGGING_VERSION}.jar")


else()
    # use system JARs

    find_file(JBOSS_LOGGING_JAR
        NAMES
            jboss-logging.jar
        PATHS
            /usr/share/java/jboss-logging
            /usr/share/java
    )
    set(JBOSS_LOGGING_LINK "../../../..${JBOSS_LOGGING_JAR}")

endif (JBOSS_LOGGING_VERSION)

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
        /usr/share/java
)

find_file(JUNIT_JUPITER_ENGINE_JAR
    NAMES
        junit-jupiter-engine.jar
    PATHS
        /usr/share/java/junit5
        /usr/share/java
)

find_file(JUNIT_PLATFORM_COMMONS_JAR
    NAMES
        junit-platform-commons.jar
    PATHS
        /usr/share/java/junit5
        /usr/share/java
)

find_file(JUNIT_PLATFORM_ENGINE_JAR
    NAMES
        junit-platform-engine.jar
    PATHS
        /usr/share/java/junit5
        /usr/share/java
)

find_file(JUNIT_PLATFORM_LAUNCHER_JAR
    NAMES
        junit-platform-launcher.jar
    PATHS
        /usr/share/java/junit5
        /usr/share/java
)

find_file(JUNIT_PLATFORM_SUITE_JAR
    NAMES
        junit-platform-suite-api.jar
    PATHS
        /usr/share/java/junit5
        /usr/share/java
)

find_file(OPENTEST4J_JAR
    NAMES
        opentest4j.jar
    PATHS
        /usr/share/java/opentest4j
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

if (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")
    execute_process(
        COMMAND ls ${CMAKE_SOURCE_DIR}/base/common/lib
        COMMAND sed -n "s/^resteasy-jaxrs-\\(.*\\)\\.jar\$/\\1/p"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE RESTEASY_VERSION
    )
endif (EXISTS "${CMAKE_SOURCE_DIR}/base/common/lib")

if (RESTEASY_VERSION)
    # use imported JARs

    set(RESTEASY_JAXRS_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/resteasy-jaxrs-${RESTEASY_VERSION}.jar")
    set(RESTEASY_JAXRS_LINK "resteasy-jaxrs-${RESTEASY_VERSION}.jar")

    set(RESTEASY_JACKSON_PROVIDER_JAR "${CMAKE_SOURCE_DIR}/base/common/lib/resteasy-jackson2-provider-${RESTEASY_VERSION}.jar")
    set(RESTEASY_JACKSON_PROVIDER_LINK "resteasy-jackson2-provider-${RESTEASY_VERSION}.jar")

    set(RESTEASY_SERVLET_INITIALIZER_JAR "${CMAKE_SOURCE_DIR}/base/server/lib/resteasy-servlet-initializer-${RESTEASY_VERSION}.jar")
    set(RESTEASY_SERVLET_INITIALIZER_LINK "resteasy-servlet-initializer-${RESTEASY_VERSION}.jar")

else()
    # use system JARs

    find_file(RESTEASY_JAXRS_JAR
        NAMES
            resteasy-jaxrs.jar
        PATHS
            /usr/share/java/resteasy
            /usr/share/java
    )
    set(RESTEASY_JAXRS_LINK "../../../..${RESTEASY_JAXRS_JAR}")

    find_file(RESTEASY_JACKSON_PROVIDER_JAR
        NAMES
            resteasy-jackson2-provider.jar
        PATHS
            /usr/share/java/resteasy
            /usr/share/java
    )
    set(RESTEASY_JACKSON_PROVIDER_LINK "../../../..${RESTEASY_JACKSON_PROVIDER_JAR}")

    find_file(RESTEASY_SERVLET_INITIALIZER_JAR
        NAMES
            resteasy-servlet-initializer.jar
        PATHS
            /usr/share/java/resteasy
            /usr/share/java
    )
    set(RESTEASY_SERVLET_INITIALIZER_LINK "../../../../../..${RESTEASY_SERVLET_INITIALIZER_JAR}")

endif (RESTEASY_VERSION)

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
        /usr/share/java
)

find_file(JSS_TOMCAT_9_0_JAR
    NAMES
        jss-tomcat-9.0.jar
    PATHS
        /usr/share/java/jss
        /usr/share/java
)

find_file(JSS_TOMCAT_10_1_JAR
    NAMES
       jss-tomcat-10.1.jar
    PATHS
       /usr/share/java/jss
       /usr/share/java
)

find_file(FONTAWESOME_WEBFONT
    NAMES
        fontawesome-webfont.woff
    PATHS
        /usr/share/fonts/fontawesome/
        /usr/share/fonts/fontawesome4/
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
        ${PKI_TOMCAT_IMPL_JAR}
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

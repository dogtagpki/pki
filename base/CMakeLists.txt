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

project(ocsp NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-ocsp
javac(pki-ocsp-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CLI_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_IO_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${JSS_JAR}
        ${JSS_TOMCAT_JAR}
        ${JSS_TOMCAT_9_0_JAR}
        ${LDAPJDK_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-ocsp-classes)

set(PKI_OCSP_JAR ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar
    CACHE INTERNAL "pki-ocsp.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-ocsp-jar
    CREATE
        ${PKI_OCSP_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-ocsp-classes
)

add_dependencies(java pki-ocsp-jar)

# Create links at /usr/share/pki/ocsp/webapps/ocsp/admin/console.
# Create links in /usr/share/pki/ocsp/webapps/ocsp/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-ocsp-links ALL
    COMMENT "Creating links for OCSP")

add_custom_command(
    TARGET pki-ocsp-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../../../..${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-ocsp.jar webapp/lib/pki-ocsp.jar
    COMMAND ln -sf ../../../../../../../..${RESTEASY_SERVLET_INITIALIZER_JAR} webapp/lib/resteasy-servlet-intializer.jar
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_OCSP_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

# install directories
install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/ocsp/database
)

install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "CMakeLists.txt" EXCLUDE
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin/
    DESTINATION
        ${DATA_INSTALL_DIR}/ocsp/webapps/ocsp/admin
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/ocsp/webapps/ocsp/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/ocsp
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/ocsp
)


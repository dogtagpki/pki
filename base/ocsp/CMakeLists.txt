project(ocsp NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-ocsp
javac(pki-ocsp-classes
    DEPENDS
        pki-common-jar pki-server-jar
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
        ${LDAPJDK_JAR}
        ${TOMCATJSS_JAR}
        ${PKI_COMMON_JAR} ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-ocsp-jar
    DEPENDS
        pki-ocsp-classes
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

# Create links at /usr/share/pki/ocsp/webapps/ocsp/admin/console.
# Create links in /usr/share/pki/ocsp/webapps/ocsp/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-ocsp-links ALL
    COMMENT "Creating links for OCSP")

add_custom_command(
    TARGET pki-ocsp-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../../../..${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-ocsp.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-ocsp.jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_OCSP_JAR ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar CACHE INTERNAL "pki-ocsp jar file")

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


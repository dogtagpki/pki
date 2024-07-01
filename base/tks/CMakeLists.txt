project(tks NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-tks
javac(pki-tks-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CLI_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_LANG3_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
        ${JAXRS_API_JAR}
        ${RESTEASY_JAXRS_JAR}
        ${PKI_COMMON_JAR} ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-tks-classes)

set(PKI_TKS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tks.jar
    CACHE INTERNAL "pki-tks.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-tks-jar
    CREATE
        ${PKI_TKS_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tks-classes
)

add_dependencies(java pki-tks-jar)

# Create links at /usr/share/pki/tks/webapps/tks/admin/console.
# Create /usr/share/pki/tks/webapps/tks/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-tks-links ALL
    COMMENT "Creating links for TKS")

add_custom_command(
    TARGET pki-tks-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../lib/slf4j-api.jar webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../lib/slf4j-jdk14.jar webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-tks.jar webapp/lib/pki-tks.jar
    COMMAND ln -sf ../../../../../server/common/lib/resteasy-servlet-initializer.jar webapp/lib/resteasy-servlet-initializer.jar
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_TKS_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

# install directories
install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/tks/database
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
        ${DATA_INSTALL_DIR}/tks/webapps/tks/admin
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/tks/webapps/tks/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tks
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tks
)


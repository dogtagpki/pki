project(server-webapp)

# build server-webapp classes
javac(pki-server-webapp-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-server-webapp-classes)

set(PKI_SERVER_WEBAPP_JAR ${CMAKE_BINARY_DIR}/dist/pki-server-webapp.jar
    CACHE INTERNAL "pki-server-webapp.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-server-webapp-jar
    CREATE
        ${PKI_SERVER_WEBAPP_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    INPUT_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources
    DEPENDS
        pki-server-webapp-classes
)

add_dependencies(java pki-server-webapp-jar)

# Create /usr/share/pki/server/webapps/pki/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-webapp-lib ALL
    COMMENT "Creating links for PKI server webapp library")

add_custom_command(
    TARGET pki-server-webapp-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../lib/slf4j-api.jar webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../lib/slf4j-jdk14.jar webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server-webapp.jar webapp/lib/pki-server-webapp.jar
    COMMAND ln -sf ../../../../../server/common/lib/resteasy-servlet-initializer.jar webapp/lib/resteasy-servlet-initializer.jar
)

install(
    DIRECTORY
        webapps
    DESTINATION
        ${DATA_INSTALL_DIR}/server
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_SERVER_WEBAPP_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/webapps/pki/WEB-INF/lib
)

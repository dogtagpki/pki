project(server-webapp)

# build server-webapp classes
javac(pki-server-webapp-classes
    DEPENDS
        pki-server-jar
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${JACKSON2_ANNOTATIONS_JAR}
        ${JACKSON2_CORE_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

# build pki-server-webapp.jar
jar(pki-server-webapp-jar
    DEPENDS
        pki-server-webapp-classes
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-server-webapp.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    INPUT_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources
)

set(PKI_SERVER_WEBAPP_JAR ${CMAKE_BINARY_DIR}/dist/pki-server-webapp.jar CACHE INTERNAL "pki-server-webapp jar file")

# Create /usr/share/pki/server/webapps/pki/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-webapp-lib ALL
    COMMENT "Creating links for PKI server webapp library")

add_custom_command(
    TARGET pki-server-webapp-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../../../..${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server-webapp.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-server-webapp.jar
)

install(
    DIRECTORY
        webapps
    DESTINATION
        ${DATA_INSTALL_DIR}/server
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-server-webapp.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/webapps/pki/WEB-INF/lib
)

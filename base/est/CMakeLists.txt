project(est NONE)

javac(pki-est-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_IO_JAR}
        ${COMMONS_LANG3_JAR}
        ${HTTPCORE_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${TOMCAT_CATALINA_JAR}
        ${TOMCAT_UTIL_JAR}
        ${JSS_JAR}
        ${PKI_CMSUTIL_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_TOMCAT_JAR}
        ${PKI_TOMCAT_IMPL_JAR}
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-est-classes)

set(PKI_EST_JAR ${CMAKE_BINARY_DIR}/dist/pki-est.jar
    CACHE INTERNAL "pki-est.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-est-jar
    CREATE
        ${PKI_EST_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-est-classes
)

add_dependencies(java pki-est-jar)

add_custom_target(pki-est-links ALL
    COMMENT "Creating links for EST")

add_custom_command(
    TARGET pki-est-links POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../lib/slf4j-api.jar webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../lib/slf4j-jdk14.jar webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-est.jar webapp/lib/pki-est.jar
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_EST_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

# install deployment descriptor
install(
    DIRECTORY
        ${APP_SERVER}/conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/est/conf/
)

# install web application files
install(
    DIRECTORY
        webapps/
    DESTINATION
        ${DATA_INSTALL_DIR}/est/webapps/
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/est/webapps/est/WEB-INF/lib
)

install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/conf/
    PATTERN
        "CMakeLists.txt" EXCLUDE
)

install(
    FILES
        bin/estauthz
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/bin/
    PERMISSIONS
	OWNER_EXECUTE OWNER_WRITE OWNER_READ
	GROUP_EXECUTE GROUP_READ
	WORLD_EXECUTE WORLD_READ
)

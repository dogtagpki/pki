project(est NONE)

javac(pki-est-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_IO_JAR}
        ${JACKSON2_ANNOTATIONS_JAR}
        ${JACKSON2_CORE_JAR}
        ${JACKSON2_DATABIND_JAR}
        ${TOMCAT_CATALINA_JAR}
        ${JSS_JAR}
        ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR}
        ${PKI_CMS_JAR}
    DEPENDS
        pki-certsrv-jar pki-cms-jar
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-est-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-est.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-est-classes
)

set(PKI_EST_JAR ${CMAKE_BINARY_DIR}/dist/pki-est.jar CACHE INTERNAL "pki-est.jar file")

add_custom_target(pki-est-links ALL
    COMMENT "Creating links for EST")

add_custom_command(
    TARGET pki-est-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-est.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-est.jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-est.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

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

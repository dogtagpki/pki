project(common NONE)

# install common configuration files
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/share/etc/pki.conf
    ${CMAKE_CURRENT_BINARY_DIR}/share/etc/pki.conf
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/etc/pki.conf
    ${CMAKE_CURRENT_BINARY_DIR}/etc/pki.conf
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pki-upgrade.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-upgrade
)

# Create /usr/share/pki/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-lib ALL
    COMMENT "Creating links for PKI common library")

add_custom_command(
    TARGET pki-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_CLI_JAR} lib/commons-cli.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_CODEC_JAR} lib/commons-codec.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_HTTPCLIENT_JAR} lib/commons-httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_IO_JAR} lib/commons-io.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_LANG_JAR} lib/commons-lang.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_LOGGING_JAR} lib/commons-logging.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${HTTPCLIENT_JAR} lib/httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${HTTPCORE_JAR} lib/httpcore.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_CORE_JAR} lib/jackson-core-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_JAXRS_JAR} lib/jackson-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_MAPPER_JAR} lib/jackson-mapper-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_MRBEAN_JAR} lib/jackson-mrbean.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_SMILE_JAR} lib/jackson-smile.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON_XC_JAR} lib/jackson-xc.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JAXB_API_JAR} lib/jaxb-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JSS_JAR} lib/jss4.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${LDAPJDK_JAR} lib/ldapjdk.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-cmsutil.jar
    COMMAND ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-nsutil.jar
    COMMAND ln -sf /usr/share/java/pki/pki-tools.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-tools.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_ATOM_PROVIDER_JAR} lib/resteasy-atom-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-client.jar lib/resteasy-client.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jackson-provider.jar lib/resteasy-jackson-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxb-provider.jar lib/resteasy-jaxb-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JAXRS_API_JAR} lib/jaxrs-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxrs.jar lib/resteasy-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SERVLET_JAR} lib/servlet.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} lib/slf4j-jdk14.jar
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/lib
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/share/etc/logging.properties
        ${CMAKE_CURRENT_BINARY_DIR}/share/etc/pki.conf
    DESTINATION
        ${DATA_INSTALL_DIR}/etc/
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/etc/pki.conf
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki/
)

# install executables
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-upgrade
    DESTINATION
        ${SBIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        scripts/config
    DESTINATION
        ${DATA_INSTALL_DIR}/scripts/
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)

install(
    DIRECTORY
        upgrade
    DESTINATION
        ${DATA_INSTALL_DIR}/
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
    PATTERN ".gitignore" EXCLUDE
)

install(
    DIRECTORY
        key
    DESTINATION
        ${DATA_INSTALL_DIR}/
    FILE_PERMISSIONS
        OWNER_READ
        GROUP_READ
        WORLD_READ
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tomcat
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tomcat
)

install(
    DIRECTORY
    DESTINATION 
        ${SYSTEMD_ETC_INSTALL_DIR}/pki-tomcatd.target.wants
)

install(
    DIRECTORY
    DESTINATION
        ${SYSTEMD_ETC_INSTALL_DIR}/pki-tomcatd-nuxwdog.target.wants
)

install(
    DIRECTORY
    DESTINATION
        /etc/sysconfig/pki
)

install(
    DIRECTORY
    DESTINATION
        /etc/sysconfig/pki/tomcat
)

install(
    DIRECTORY
        man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(python)

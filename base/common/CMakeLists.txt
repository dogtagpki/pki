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

# Create /usr/share/pki/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-lib ALL)

add_custom_command(
    TARGET pki-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-cli.jar lib/commons-cli.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-codec.jar lib/commons-codec.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-httpclient.jar lib/commons-httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-io.jar lib/commons-io.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-lang.jar lib/commons-lang.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-logging.jar lib/commons-logging.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/httpcomponents/httpclient.jar lib/httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/httpcomponents/httpcore.jar lib/httpcore.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-core-asl.jar lib/jackson-core-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-jaxrs.jar lib/jackson-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-mapper-asl.jar lib/jackson-mapper-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-mrbean.jar lib/jackson-mrbean.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-smile.jar lib/jackson-smile.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-xc.jar lib/jackson-xc.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jaxb-api.jar lib/jaxb-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/lib/java/jss4.jar lib/jss4.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/ldapjdk.jar lib/ldapjdk.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-certsrv.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-cmsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-nsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-tools.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-tools.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-atom-provider.jar lib/resteasy-atom-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-client.jar lib/resteasy-client.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jackson-provider.jar lib/resteasy-jackson-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxb-provider.jar lib/resteasy-jaxb-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/jaxrs-api.jar lib/resteasy-jaxrs-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxrs-jandex.jar lib/resteasy-jaxrs-jandex.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxrs.jar lib/resteasy-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/servlet.jar lib/servlet.jar
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
        sbin/pki-upgrade
    DESTINATION
        ${SBIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
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
        man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

add_subdirectory(src)
add_subdirectory(python)

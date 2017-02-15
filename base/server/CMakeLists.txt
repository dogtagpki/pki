project(server)

set(PKI_SUBSYSTEMS
    ca
    kra
    ocsp
    ra
    tks
    tps
)

set(TOMCAT_SUBSYSTEMS
    ca
    kra
    ocsp
    tks
)

set(APACHE_SUBSYSTEMS
    ra
    tps
)

# Create /usr/share/pki/server/common/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-common-lib ALL)

add_custom_command(
    TARGET pki-server-common-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory common/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-codec.jar common/lib/commons-codec.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-collections.jar common/lib/commons-collections.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-io.jar common/lib/commons-io.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-lang.jar common/lib/commons-lang.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/commons-logging.jar common/lib/commons-logging.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/httpcomponents/httpclient.jar common/lib/httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/httpcomponents/httpcore.jar common/lib/httpcore.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-core-asl.jar common/lib/jackson-core-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-jaxrs.jar common/lib/jackson-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-mapper-asl.jar common/lib/jackson-mapper-asl.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-mrbean.jar common/lib/jackson-mrbean.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-smile.jar common/lib/jackson-smile.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/jackson/jackson-xc.jar common/lib/jackson-xc.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/javassist.jar common/lib/javassist.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/lib/java/jss4.jar common/lib/jss4.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/ldapjdk.jar common/lib/ldapjdk.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/lib/java/nuxwdog.jar common/lib/nuxwdog.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-tomcat.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/pki-tomcat.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-atom-provider.jar common/lib/resteasy-atom-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-client.jar common/lib/resteasy-client.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jackson-provider.jar common/lib/resteasy-jackson-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxb-provider.jar common/lib/resteasy-jaxb-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/jaxrs-api.jar common/lib/resteasy-jaxrs-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxrs.jar common/lib/resteasy-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/scannotation.jar common/lib/scannotation.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} common/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} common/lib/slf4j-jdk14.jar
    COMMAND /usr/bin/ln -sf /usr/lib/java/symkey.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/symkey.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/tomcatjss.jar common/lib/tomcatjss.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/velocity.jar common/lib/velocity.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/xerces-j2.jar common/lib/xerces-j2.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/xml-commons-apis.jar common/lib/xml-commons-apis.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/xml-commons-resolver.jar common/lib/xml-commons-resolver.jar
)

# Create /usr/share/pki/server/webapps/pki/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-webapp-lib ALL)

add_custom_command(
    TARGET pki-server-webapp-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-nsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmscore.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmscore.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/common/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/common/lib
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/webapps/pki/WEB-INF/lib
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

# install Python libraries (Python 2 only)
install(
    DIRECTORY
        python/pki/server
    DESTINATION
        ${PYTHON2_SITE_PACKAGES}/pki
    FILES_MATCHING PATTERN
        *.py
)

# install systemd scripts
install(
    DIRECTORY
        share/lib/systemd/system/
    DESTINATION
        ${SYSTEMD_LIB_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        setup/CertServer.directory
        setup/menu.xml
        setup/pkidaemon_registry
    DESTINATION
        ${DATA_INSTALL_DIR}/setup/
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)

# install executables
install(
    DIRECTORY
        sbin/
    DESTINATION
        ${SBIN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        upgrade
    DESTINATION
        ${DATA_INSTALL_DIR}/server/
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
    PATTERN ".gitignore" EXCLUDE
)

install(
    FILES
        scripts/pkidaemon
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        scripts/operations
    DESTINATION
        ${DATA_INSTALL_DIR}/scripts/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        config
    DESTINATION
        ${DATA_INSTALL_DIR}/deployment
)

# install server files
install(
    DIRECTORY
        share/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/
    PATTERN
        "lib/*" EXCLUDE
)

# install server configuration files
install(
    DIRECTORY
        etc/
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki
)

# install empty directories
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/lock/pki)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/run/pki)")

if(WITH_TOMCAT7)
    add_subdirectory(tomcat7)
endif(WITH_TOMCAT7)

if(WITH_TOMCAT8)
    add_subdirectory(tomcat8)
endif(WITH_TOMCAT8)

add_subdirectory(tomcat)
add_subdirectory(cms)
add_subdirectory(cmsbundle)
add_subdirectory(cmscore)
add_subdirectory(test)

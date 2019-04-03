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

add_subdirectory(${APP_SERVER})
add_subdirectory(tomcat)
add_subdirectory(cms)
add_subdirectory(cmsbundle)
add_subdirectory(cmscore)
add_subdirectory(test)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/share/etc/tomcat.conf.in
    ${CMAKE_CURRENT_BINARY_DIR}/share/etc/tomcat.conf
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pki-server.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-server
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pki-server-upgrade.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-server-upgrade
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pkidestroy.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbin/pkidestroy
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pkispawn.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbin/pkispawn
)

# build server classes
javac(pki-server-classes
    SOURCES
        cms/src/*.java
        cmscore/src/*.java
    CLASSPATH
        ${SLF4J_API_JAR} ${JAXB_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR} ${COMMONS_IO_JAR} ${COMMONS_LANG_JAR}
        ${HTTPCORE_JAR} ${HTTPCLIENT_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${XALAN_JAR} ${XERCES_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${TOMCATJSS_JAR} ${VELOCITY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_TOMCAT_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-tools-jar pki-tomcat-jar
)

# build pki-cms.jar
jar(pki-cms-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/cms/src/pki-cms.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    FILES
        com/netscape/cms/*
        org/dogtagpki/legacy/server/policy/*
        org/dogtagpki/server/*
    DEPENDS
        pki-server-classes
)

# build pki-cmscore.jar
jar(pki-cmscore-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/cmscore/src/pki-cmscore.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    FILES
        com/netscape/cmscore/*
        org/dogtagpki/legacy/core/policy/*
    DEPENDS
        pki-server-classes
)

# Create /usr/share/pki/server/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-lib ALL
    COMMENT "Creating links for PKI server library")

add_custom_command(
    TARGET pki-server-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} lib/slf4j-jdk14.jar
)

# Create /usr/share/pki/server/common/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-common-lib ALL
    COMMENT "Creating links for PKI server common library")

add_custom_command(
    TARGET pki-server-common-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory common/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_CODEC_JAR} common/lib/commons-codec.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_COLLECTIONS_JAR} common/lib/commons-collections.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_IO_JAR} common/lib/commons-io.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_LANG_JAR} common/lib/commons-lang.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${COMMONS_LOGGING_JAR} common/lib/commons-logging.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${HTTPCLIENT_JAR} common/lib/httpclient.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${HTTPCORE_JAR} common/lib/httpcore.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_CORE_JAR} common/lib/jackson-core.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_DATABIND_JAR} common/lib/jackson-databind.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_ANNOTATIONS_JAR} common/lib/jackson-annotations.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_JAXRS_BASE_JAR} common/lib/jackson-jaxrs-base.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_JAXRS_JSON_PROVIDER_JAR} common/lib/jackson-jaxrs-json-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JACKSON2_JAXB_ANNOTATIONS_JAR} common/lib/jackson-module-jaxb-annotations.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/javassist.jar common/lib/javassist.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JSS_JAR} common/lib/jss4.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${LDAPJDK_JAR} common/lib/ldapjdk.jar
    COMMAND ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/pki-nsutil.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/pki-cmsutil.jar
    COMMAND ln -sf /usr/share/java/pki/pki-tomcat.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/pki-tomcat.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-atom-provider.jar common/lib/resteasy-atom-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-client.jar common/lib/resteasy-client.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jackson2-provider.jar common/lib/resteasy-jackson2-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxb-provider.jar common/lib/resteasy-jaxb-provider.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${JAXRS_API_JAR} common/lib/jaxrs-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${RESTEASY_LIB}/resteasy-jaxrs.jar common/lib/resteasy-jaxrs.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/scannotation.jar common/lib/scannotation.jar
    COMMAND ln -sf /usr/lib/java/symkey.jar ${CMAKE_CURRENT_BINARY_DIR}/common/lib/symkey.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${TOMCATJSS_JAR} common/lib/tomcatjss.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${VELOCITY_JAR} common/lib/velocity.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${XERCES_JAR} common/lib/xerces-j2.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${XML_COMMONS_APIS_JAR} common/lib/xml-commons-apis.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${XML_COMMONS_RESOLVER_JAR} common/lib/xml-commons-resolver.jar
)

# Create /usr/share/pki/server/webapps/pki/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-server-webapp-lib ALL
    COMMENT "Creating links for PKI webapp library")

add_custom_command(
    TARGET pki-server-webapp-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmscore.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmscore.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
)

add_custom_target(pki-server-man ALL
    COMMENT "Creating PKI server manuals")

add_custom_command(
    TARGET pki-server-man
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/man/man5
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man5/pki-server-logging.5.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man5/pki-server-logging.5
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/man/man8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-ca.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-ca.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-cert.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-cert.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-instance.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-instance.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-kra.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-kra.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-migrate.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-migrate.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-nuxwdog.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-nuxwdog.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-ocsp.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-ocsp.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-subsystem.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-subsystem.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-tks.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-tks.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-tps.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-tps.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-server-upgrade.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-server-upgrade.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pkidestroy.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pkidestroy.8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pkispawn.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pkispawn.8
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lib/pki
)

install(
    FILES
         ${CMAKE_CURRENT_BINARY_DIR}/share/etc/tomcat.conf
    DESTINATION
        ${DATA_INSTALL_DIR}/etc/
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/lib
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
        ../../docs/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/docs
)

# install static man pages
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

# install man pages generated by md2man
install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

# install Python libraries
if(WITH_PYTHON3_DEFAULT)
    install(
        DIRECTORY
            python/pki/server
        DESTINATION
            ${PYTHON3_SITE_PACKAGES}/pki
        FILES_MATCHING PATTERN
            *.py
    )
else()
    install(
        DIRECTORY
            python/pki/server
        DESTINATION
            ${PYTHON2_SITE_PACKAGES}/pki
        FILES_MATCHING PATTERN
            *.py
    )
endif()

# install systemd scripts
install(
    DIRECTORY
        share/lib/systemd/system/
    DESTINATION
        ${SYSTEMD_LIB_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
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
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-server
        ${CMAKE_CURRENT_BINARY_DIR}/sbin/pki-server-upgrade
        ${CMAKE_CURRENT_BINARY_DIR}/sbin/pkidestroy
        ${CMAKE_CURRENT_BINARY_DIR}/sbin/pkispawn
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
        ${DATA_INSTALL_DIR}/server/
    FILE_PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
    PATTERN ".gitignore" EXCLUDE
)

install(
    FILES
        scripts/pkidaemon
        scripts/pki-server-nuxwdog
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
    PATTERN
        "etc/*" EXCLUDE
)

# install server configuration files
install(
    DIRECTORY
        etc
    DESTINATION
        ${DATA_INSTALL_DIR}/server
)

# install empty directories
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/lock/pki)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/run/pki)")

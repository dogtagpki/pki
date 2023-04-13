project(common NONE)

# build pki-common
javac(pki-common-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR}
        ${JSS_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${COMMONS_LANG3_JAR} ${COMMONS_CLI_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JAVAX_ANNOTATIONS_API_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_CLIENT_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JAXB_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

# Customize default pki.conf.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/share/etc/pki.conf
    ${CMAKE_CURRENT_BINARY_DIR}/share/etc/pki.conf
)

jar(pki-common-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-common.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-classes
)

set(PKI_COMMON_JAR ${CMAKE_BINARY_DIR}/dist/pki-common.jar CACHE INTERNAL "pki-common jar file")

if(RUN_TESTS)
    javac(pki-common-test-classes
        SOURCES
            src/test/java/*.java
        CLASSPATH
            ${JAVAX_ACTIVATION_JAR}
            ${JAXB_API_JAR} ${JAXB_IMPL_JAR}
            ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
            ${JSS_JAR}
            ${COMMONS_CLI_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
            ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
            ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
            ${PKI_COMMON_JAR}
            ${HAMCREST_JAR} ${JUNIT_JAR} ${JAXRS_API_JAR}
        OUTPUT_DIR
            ${CMAKE_BINARY_DIR}/test/classes
        DEPENDS
            pki-common-jar
    )

    execute_process(
        COMMAND bash "-c"
        "grep -ilR @Test ${PROJECT_SOURCE_DIR} \
        | cut -d':' -f1 \
        | awk -F '/src/test/java/' '{ print $2 }' \
        | sed 's/.java/;/g' \
        | sed 's!/!.!g' \
        | tr -d '\n'"
        OUTPUT_VARIABLE DISCOVERED_TESTS
    )
    
    add_junit_test(test-pki-common
        CLASSPATH
            ${JAVAX_ACTIVATION_JAR}
            ${JAXB_API_JAR} ${JAXB_IMPL_JAR}
            ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
            ${JSS_JAR}
            ${COMMONS_CLI_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
            ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
            ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
            ${PKI_COMMON_JAR}
            ${HAMCREST_JAR} ${JUNIT_JAR} ${JAXRS_API_JAR}
            ${CMAKE_BINARY_DIR}/test/classes
        TESTS
            ${DISCOVERED_TESTS}
        REPORTS_DIR
            reports
        DEPENDS
            pki-common-test-classes
    )
endif(RUN_TESTS)

# Create /usr/share/pki/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-lib ALL
    COMMENT "Creating links for PKI common library")

add_custom_command(
    TARGET pki-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND ln -sf ../../../..${COMMONS_CLI_JAR} lib/commons-cli.jar
    COMMAND ln -sf ../../../..${COMMONS_CODEC_JAR} lib/commons-codec.jar
    COMMAND ln -sf ../../../..${COMMONS_IO_JAR} lib/commons-io.jar
    COMMAND ln -sf ../../../..${COMMONS_LANG3_JAR} lib/commons-lang3.jar
    COMMAND ln -sf ../../../..${COMMONS_LOGGING_JAR} lib/commons-logging.jar
    COMMAND ln -sf ../../../..${COMMONS_NET_JAR} lib/commons-net.jar
    COMMAND ln -sf ../../../..${HTTPCLIENT_JAR} lib/httpclient.jar
    COMMAND ln -sf ../../../..${HTTPCORE_JAR} lib/httpcore.jar
    COMMAND ln -sf ../../../..${JACKSON2_CORE_JAR} lib/jackson-core.jar
    COMMAND ln -sf ../../../..${JACKSON2_DATABIND_JAR} lib/jackson-databind.jar
    COMMAND ln -sf ../../../..${JACKSON2_ANNOTATIONS_JAR} lib/jackson-annotations.jar
    COMMAND ln -sf ../../../..${JACKSON2_JAXRS_BASE_JAR} lib/jackson-jaxrs-base.jar
    COMMAND ln -sf ../../../..${JACKSON2_JAXRS_JSON_PROVIDER_JAR} lib/jackson-jaxrs-json-provider.jar
    COMMAND ln -sf ../../../..${JACKSON2_JAXB_ANNOTATIONS_JAR} lib/jackson-module-jaxb-annotations.jar
    COMMAND ln -sf ../../../..${JAVAX_ACTIVATION_JAR} lib/javax.activation.jar
    COMMAND ln -sf ../../../..${JAVAX_ANNOTATIONS_API_JAR} lib/javax.annotations-api.jar
    COMMAND ln -sf ../../../..${JAXB_API_JAR} lib/jaxb-api.jar
    COMMAND ln -sf ../../../..${JAXRS_API_JAR} lib/jaxrs-api.jar
    COMMAND ln -sf ../../../..${JBOSS_LOGGING_JAR} lib/jboss-logging.jar
    COMMAND ln -sf ../../../..${JSS_JAR} lib/jss.jar
    COMMAND ln -sf ../../../..${LDAPJDK_JAR} lib/ldapjdk.jar
    COMMAND ln -sf ../../../..${P11_KIT_TRUST} lib/p11-kit-trust.so
    COMMAND ln -sf ../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-common.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-common.jar
    COMMAND ln -sf ../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-tools.jar ${CMAKE_CURRENT_BINARY_DIR}/lib/pki-tools.jar
    COMMAND ln -sf ../../../..${RESTEASY_CLIENT_JAR} lib/resteasy-client.jar
    COMMAND ln -sf ../../../..${RESTEASY_JACKSON2_PROVIDER_JAR} lib/resteasy-jackson2-provider.jar
    COMMAND ln -sf ../../../..${RESTEASY_JAXRS_JAR} lib/resteasy-jaxrs.jar
    COMMAND ln -sf ../../../..${SERVLET_JAR} lib/servlet.jar
    COMMAND ln -sf ../../../..${SLF4J_API_JAR} lib/slf4j-api.jar
    COMMAND ln -sf ../../../..${SLF4J_JDK14_JAR} lib/slf4j-jdk14.jar
)

add_custom_target(pki-man ALL
    COMMENT "Creating PKI manuals")

add_custom_command(
    TARGET pki-man
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/man/man5
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man5/pki-logging.5.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man5/pki-logging.5
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/man/man8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-upgrade.8.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man8/pki-upgrade.8
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-common.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
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
        ${CMAKE_CURRENT_SOURCE_DIR}/etc/pki.conf
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki/
)

# install executables
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/sbin/pki-upgrade
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
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
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
        ${VAR_INSTALL_DIR}/log/pki
)

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

add_subdirectory(examples)
add_subdirectory(python)

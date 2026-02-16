project(common NONE)

# build pki-common
javac(pki-common-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${COMMONS_LANG3_JAR} ${COMMONS_CLI_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
        ${JAKARTA_ANNOTATION_API_JAR}
        ${JAXRS_API_JAR}
        ${RESTEASY_JAXRS_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JAXB_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

add_dependencies(java pki-common-classes)

set(PKI_COMMON_JAR ${CMAKE_BINARY_DIR}/dist/pki-common.jar
    CACHE INTERNAL "pki-common.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-common-jar
    CREATE
        ${PKI_COMMON_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-classes
)

add_dependencies(java pki-common-jar)

if(RUN_TESTS)
    javac(pki-common-test-classes
        SOURCES
            src/test/java/*.java
        CLASSPATH
            ${JAKARTA_ACTIVATION_API_JAR}
            ${JAXB_API_JAR} ${JAXB_IMPL_JAR}
            ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
            ${JSS_JAR}
            ${COMMONS_CLI_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
            ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
            ${JACKSON_ANNOTATIONS_JAR}
            ${JACKSON_CORE_JAR}
            ${JACKSON_DATABIND_JAR}
            ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
            ${JAXRS_API_JAR}
            ${PKI_COMMON_JAR}
            ${HAMCREST_JAR}
            ${JUNIT_JUPITER_API_JAR} ${JUNIT_PLATFORM_LAUNCHER_JAR} ${JUNIT_PLATFORM_SUITE_JAR}
            ${JUNIT_PLATFORM_ENGINE_JAR} ${JUNIT_PLATFORM_COMMONS_JAR} ${JUNIT_JUPITER_ENGINE_JAR}
            ${OPENTEST4J_JAR}
        OUTPUT_DIR
            ${CMAKE_BINARY_DIR}/test/classes
        DEPENDS
            pki-common-jar
    )

    add_dependencies(java pki-common-test-classes)

    add_junit_test(test-pki-common
        CLASSPATH
            ${JAKARTA_ACTIVATION_JAR}
            ${JAXB_API_JAR} ${JAXB_IMPL_JAR}
            ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
            ${JSS_JAR}
            ${COMMONS_CLI_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
            ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
            ${JACKSON_ANNOTATIONS_JAR}
            ${JACKSON_CORE_JAR}
            ${JACKSON_DATABIND_JAR}
            ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
            ${JAXRS_API_JAR}
            ${PKI_COMMON_JAR}
            ${HAMCREST_JAR}
            ${CMAKE_BINARY_DIR}/test/classes
            ${JUNIT_JUPITER_API_JAR} ${JUNIT_PLATFORM_LAUNCHER_JAR} ${JUNIT_PLATFORM_SUITE_JAR}
            ${JUNIT_PLATFORM_ENGINE_JAR} ${JUNIT_PLATFORM_COMMONS_JAR} ${JUNIT_JUPITER_ENGINE_JAR}
            ${OPENTEST4J_JAR}
        REPORTS_DIR
            reports
        DEPENDS
            pki-common-test-classes
    )

    add_dependencies(java test-pki-common)

endif(RUN_TESTS)

# Create /usr/share/pki/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-lib ALL
    COMMENT "Creating links for PKI common library")

add_custom_command(
    TARGET pki-lib POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND test ! -d ${CMAKE_SOURCE_DIR}/base/common/lib || cp ${CMAKE_SOURCE_DIR}/base/common/lib/* lib
    COMMAND ln -sf ${COMMONS_CLI_LINK} lib/commons-cli.jar
    COMMAND ln -sf ${COMMONS_CODEC_LINK} lib/commons-codec.jar
    COMMAND ln -sf ${COMMONS_IO_LINK} lib/commons-io.jar
    COMMAND ln -sf ${COMMONS_LANG3_LINK} lib/commons-lang3.jar
    COMMAND ln -sf ${COMMONS_LOGGING_LINK} lib/commons-logging.jar
    COMMAND ln -sf ${COMMONS_NET_LINK} lib/commons-net.jar
    COMMAND ln -sf ${HTTPCLIENT_LINK} lib/httpclient.jar
    COMMAND ln -sf ${HTTPCORE_LINK} lib/httpcore.jar
    COMMAND ln -sf ${JACKSON_ANNOTATIONS_LINK} lib/jackson-annotations.jar
    COMMAND ln -sf ${JACKSON_CORE_LINK} lib/jackson-core.jar
    COMMAND ln -sf ${JACKSON_DATABIND_LINK} lib/jackson-databind.jar
    COMMAND ln -sf ${JACKSON_JAXRS_BASE_LINK} lib/jackson-jaxrs-base.jar
    COMMAND ln -sf ${JACKSON_JAXRS_JSON_PROVIDER_LINK} lib/jackson-jaxrs-json-provider.jar
    COMMAND ln -sf ${JACKSON_MODULE_JAXB_ANNOTATIONS_LINK} lib/jackson-module-jaxb-annotations.jar
    COMMAND ln -sf ${JAKARTA_ACTIVATION_API_LINK} lib/jakarta.activation-api.jar
    COMMAND ln -sf ${JAKARTA_ANNOTATION_API_LINK} lib/jakarta.annotation-api.jar
    COMMAND ln -sf ${JAXB_API_LINK} lib/jakarta.xml.bind-api.jar
    COMMAND ln -sf ${JAXRS_API_LINK} lib/jboss-jaxrs-api_2.0_spec.jar
    COMMAND ln -sf ${JBOSS_LOGGING_LINK} lib/jboss-logging.jar
    COMMAND ln -sf ../../../..${JSS_JAR} lib/jss.jar
    COMMAND ln -sf ../../../..${LDAPJDK_JAR} lib/ldapjdk.jar
    COMMAND ln -sf ../../../..${P11_KIT_TRUST} lib/p11-kit-trust.so
    COMMAND ln -sf ../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-common.jar lib/pki-common.jar
    COMMAND ln -sf ../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-tools.jar lib/pki-tools.jar
    COMMAND ln -sf ${RESTEASY_JACKSON_PROVIDER_LINK} lib/resteasy-jackson2-provider.jar
    COMMAND ln -sf ${RESTEASY_JAXRS_LINK} lib/resteasy-jaxrs.jar
    COMMAND ln -sf ../../../..${SERVLET_JAR} lib/servlet.jar
    COMMAND ln -sf ${SLF4J_API_LINK} lib/slf4j-api.jar
    COMMAND ln -sf ${SLF4J_JDK14_LINK} lib/slf4j-jdk14.jar
)

add_custom_target(pki-man ALL
    COMMENT "Creating PKI manuals")

add_custom_command(
    TARGET pki-man POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory man/man5
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man5/pki-logging.5.md -out man/man5/pki-logging.5
    COMMAND ${CMAKE_COMMAND} -E make_directory man/man8
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man8/pki-upgrade.8.md -out man/man8/pki-upgrade.8
)

# Customize default pki.conf.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/share/etc/pki.conf
    ${CMAKE_CURRENT_BINARY_DIR}/share/etc/pki.conf
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_COMMON_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

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

project(pki-ca_java NONE)

# '/usr/share/java' jars
find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        /usr/share/java
)


# '${JAVA_LIB_INSTALL_DIR}' jars
find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_IO_JAR
    NAMES
        commons-io.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_LANG_JAR
    NAMES
        commons-lang.jar
    PATHS
        /usr/share/java
)

find_file(JACKSON_CORE_JAR
    NAMES
        jackson-core-asl.jar
    PATHS
        /usr/share/java/jackson
)

find_file(JACKSON_MAPPER_JAR
    NAMES
        jackson-mapper-asl.jar
    PATHS
        /usr/share/java/jackson
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
)

# build pki-ca
javac(pki-ca-classes
    SOURCES
        *.java
    CLASSPATH
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR} ${COMMONS_LANG_JAR}
        ${JACKSON_CORE_JAR} ${JACKSON_MAPPER_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar pki-cmscore-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-ca.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-ca.mf
)

jar(pki-ca-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-ca.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-ca-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CA_JAR ${CMAKE_BINARY_DIR}/dist/pki-ca.jar CACHE INTERNAL "pki-ca jar file")

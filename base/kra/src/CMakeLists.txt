project(pki-kra_java NONE)

# '/usr/share/java/pki' jars
find_file(PKI_CERTSRV_JAR
    NAMES
        pki-certsrv.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMS_JAR
    NAMES
        pki-cms.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMSCORE_JAR
    NAMES
        pki-cmscore.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMSUTIL_JAR
    NAMES
        pki-cmsutil.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_NSUTIL_JAR
    NAMES
        pki-nsutil.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java/pki
)


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

find_file(SERVLET_JAR
    NAMES
        servlet.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(SYMKEY_JAR
    NAMES
        symkey.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)

find_file(COMMONS_LANG_JAR
    NAMES
	commons-lang.jar
    PATHS
	/usr/share/java
)

find_file(TOMCAT_CATALINA_JAR
    NAMES
        catalina.jar
    PATHS
        /usr/share/java/tomcat
)

# build pki-kra
javac(pki-kra-classes
    SOURCES
        com/netscape/kra/*.java
        org/dogtagpki/server/kra/*.java
    CLASSPATH
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${TOMCAT_CATALINA_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar pki-cmscore-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-kra.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-kra.mf
)

jar(pki-kra-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-kra.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/kra/*.class
        org/dogtagpki/server/kra/*.class
    DEPENDS
        pki-kra-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_KRA_JAR ${CMAKE_BINARY_DIR}/dist/pki-kra.jar CACHE INTERNAL "pki-kra jar file")

project(pki-ca_java Java)

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


# identify java sources
set(pki-ca_java_SRCS
    com/netscape/ca/CMSCRLExtensions.java
    com/netscape/ca/CAService.java
    com/netscape/ca/SigningUnit.java
    com/netscape/ca/CRLWithExpiredCerts.java
    com/netscape/ca/CRLIssuingPoint.java
    com/netscape/ca/CAPolicy.java
    com/netscape/ca/CertificateAuthority.java
)


# set classpath
set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
    ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
    ${LDAPJDK_JAR}
    ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR})


# set version
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})


# build pki-ca.jar
add_jar(pki-ca ${pki-ca_java_SRCS})
add_dependencies(pki-ca symkey pki-nsutil pki-cmsutil pki-certsrv pki-cms pki-cmscore)
install_jar(pki-ca ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_CA_JAR ${pki-ca_JAR_FILE} CACHE INTERNAL "pki-ca jar file")


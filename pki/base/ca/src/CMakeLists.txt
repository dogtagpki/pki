project(ca_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

set(ca_java_SRCS
    com/netscape/ca/CMSCRLExtensions.java
    com/netscape/ca/CAService.java
    com/netscape/ca/SigningUnit.java
    com/netscape/ca/CRLWithExpiredCerts.java
    com/netscape/ca/CRLIssuingPoint.java
    com/netscape/ca/CAPolicy.java
    com/netscape/ca/CertificateAuthority.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${JSS_JAR} ${LDAPJDK_JAR} ${NSUTIL_JAR} ${CMSUTIL_JAR}
    ${OSUTIL_JAR} ${SYMKEY_JAR} ${CMS_JAR} ${CMSCORE_JAR}
    ${CERTSRV_JAR})
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(ca ${ca_java_SRCS})
add_dependencies(ca nsutil cmsutil osutil symkey cms cmscore certsrv)
install_jar(ca ${JAVA_JAR_INSTALL_DIR})
set(CA_JAR ${ca_JAR_FILE} CACHE INTERNAL "ca jar file")

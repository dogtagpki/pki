project(ca_java Java)

# '/usr/share/java' jars
find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        /usr/share/java
)


# '/usr/lib/java' jars
find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        /usr/lib/java
)

find_file(OSUTIL_JAR
    NAMES
        osutil.jar
    PATHS
        /usr/lib/java
)


# identify java sources
set(ca_java_SRCS
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
    ${CERTSRV_JAR} ${CMS_JAR} ${CMSCORE_JAR} ${CMSUTIL_JAR} ${NSUTIL_JAR}
    ${LDAPJDK_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR})


# set version
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})


# build ca.jar
add_jar(ca ${ca_java_SRCS})
add_dependencies(ca osutil symkey nsutil cmsutil certsrv cms cmscore)
install_jar(ca ${JAVA_JAR_INSTALL_DIR})
set(CA_JAR ${ca_JAR_FILE} CACHE INTERNAL "ca jar file")


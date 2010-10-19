project(ocsp_java Java)

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

set(ocsp_java_SRCS
    com/netscape/ocsp/OCSPResources.java
    com/netscape/ocsp/OCSPAuthority.java
    com/netscape/ocsp/SigningUnit.java
    com/netscape/ocsp/EOCSPException.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${JSS_JAR} ${LDAPJDK_JAR} ${NSUTIL_JAR} ${CMSUTIL_JAR}
    ${OSUTIL_JAR} ${SYMKEY_JAR} ${CMS_JAR} ${CMSCORE_JAR}
    ${CERTSRV_JAR})
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(ocsp ${ocsp_java_SRCS})
add_dependencies(ocsp nsutil cmsutil osutil symkey cms cmscore certsrv)
install_jar(ocsp ${JAVA_JAR_INSTALL_DIR}/pki)
set(OCSP_JAR ${ocsp_JAR_FILE} CACHE INTERNAL "ocsp jar file")

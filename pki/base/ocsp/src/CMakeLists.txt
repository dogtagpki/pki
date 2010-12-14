project(ocsp_java Java)

# '/usr/share/java/pki' jars
find_file(CERTSRV_JAR
    NAMES
        certsrv.jar
    PATHS
        /usr/share/java/pki
)

find_file(CMS_JAR
    NAMES
        cms.jar
    PATHS
        /usr/share/java/pki
)

find_file(CMSCORE_JAR
    NAMES
        cmscore.jar
    PATHS
        /usr/share/java/pki
)

find_file(CMSUTIL_JAR
    NAMES
        cmsutil.jar
    PATHS
        /usr/share/java/pki
)

find_file(NSUTIL_JAR
    NAMES
        nsutil.jar
    PATHS
        /usr/lib/java
        /usr/share/java/pki
)


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

find_file(SYMKEY_JAR
    NAMES
        symkey.jar
    PATHS
        /usr/lib/java
)


# identify java sources
set(ocsp_java_SRCS
    com/netscape/ocsp/OCSPResources.java
    com/netscape/ocsp/OCSPAuthority.java
    com/netscape/ocsp/SigningUnit.java
    com/netscape/ocsp/EOCSPException.java
)


# set classpath
set(CMAKE_JAVA_INCLUDE_PATH
    ${CERTSRV_JAR} ${CMS_JAR} ${CMSCORE_JAR} ${CMSUTIL_JAR} ${NSUTIL_JAR}
    ${LDAPJDK_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR})


# set version
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})


# build ocsp.jar
add_jar(ocsp ${ocsp_java_SRCS})
add_dependencies(ocsp osutil symkey nsutil cmsutil certsrv cms cmscore)
install_jar(ocsp ${JAVA_JAR_INSTALL_DIR})
set(OCSP_JAR ${ocsp_JAR_FILE} CACHE INTERNAL "ocsp jar file")


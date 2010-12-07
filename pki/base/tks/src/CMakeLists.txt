project(tks_java Java)

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

set(tks_java_SRCS
    com/netscape/tks/TKSAuthority.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${JSS_JAR} ${LDAPJDK_JAR} ${NSUTIL_JAR} ${CMSUTIL_JAR}
    ${OSUTIL_JAR} ${SYMKEY_JAR} ${CMS_JAR} ${CMSCORE_JAR}
    ${CERTSRV_JAR})
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(tks ${tks_java_SRCS})
add_dependencies(tks nsutil cmsutil osutil symkey cms cmscore certsrv)
install_jar(tks ${JAVA_JAR_INSTALL_DIR})
set(TKS_JAR ${tks_JAR_FILE} CACHE INTERNAL "tks jar file")

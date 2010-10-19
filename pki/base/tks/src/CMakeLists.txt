project(tks_java Java)

set(TKS_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/tks.dir/" PARENT_SCOPE)
set(TKS_JAR "${CMAKE_CURRENT_BINARY_DIR}/tks.jar" CACHE INTERNAL "tks jar file")

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

add_jar(tks ${tks_java_SRCS})
add_dependencies(tks nsutil cmsutil osutil symkey cms cmscore certsrv)

install(
    FILES
        ${TKS_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

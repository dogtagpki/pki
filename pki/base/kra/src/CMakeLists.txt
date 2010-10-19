project(kra_java Java)

set(KRA_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/kra.dir/" PARENT_SCOPE)
set(KRA_JAR "${CMAKE_CURRENT_BINARY_DIR}/kra.jar" CACHE INTERNAL "kra jar file")

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

set(kra_java_SRCS
    com/netscape/kra/KeyRecoveryAuthority.java
    com/netscape/kra/EnrollmentService.java
    com/netscape/kra/RecoveryService.java
    com/netscape/kra/TokenKeyRecoveryService.java
    com/netscape/kra/EncryptionUnit.java
    com/netscape/kra/KRAService.java
    com/netscape/kra/NetkeyKeygenService.java
    com/netscape/kra/KRANotify.java
    com/netscape/kra/KRAPolicy.java
    com/netscape/kra/TransportKeyUnit.java
    com/netscape/kra/StorageKeyUnit.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${JSS_JAR} ${LDAPJDK_JAR} ${NSUTIL_JAR} ${CMSUTIL_JAR}
    ${OSUTIL_JAR} ${SYMKEY_JAR} ${CMS_JAR} ${CMSCORE_JAR}
    ${CERTSRV_JAR})

add_jar(kra ${kra_java_SRCS})
add_dependencies(kra nsutil cmsutil osutil symkey cms cmscore certsrv)

install(
    FILES
        ${KRA_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

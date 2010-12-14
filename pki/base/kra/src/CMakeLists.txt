project(kra_java Java)

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


# set classpath
set(CMAKE_JAVA_INCLUDE_PATH
    ${CERTSRV_JAR} ${CMS_JAR} ${CMSCORE_JAR} ${CMSUTIL_JAR} ${NSUTIL_JAR}
    ${LDAPJDK_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR})


# set version
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})


# build kra.jar
add_jar(kra ${kra_java_SRCS})
add_dependencies(kra osutil symkey nsutil cmsutil certsrv cms cmscore)
install_jar(kra ${JAVA_JAR_INSTALL_DIR})
set(KRA_JAR ${kra_JAR_FILE} CACHE INTERNAL "kra jar file")


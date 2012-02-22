project(pki-kra_java Java)

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

find_file(OSUTIL_JAR
    NAMES
        osutil.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(SYMKEY_JAR
    NAMES
        symkey.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)


# identify java sources
set(pki-kra_java_SRCS
    com/netscape/kra/KeyRecoveryAuthority.java
    com/netscape/kra/EnrollmentService.java
    com/netscape/kra/RecoveryService.java
    com/netscape/kra/SecurityDataRecoveryService.java
    com/netscape/kra/TokenKeyRecoveryService.java
    com/netscape/kra/EncryptionUnit.java
    com/netscape/kra/KRAService.java
    com/netscape/kra/NetkeyKeygenService.java
    com/netscape/kra/SecurityDataService.java
    com/netscape/kra/KRANotify.java
    com/netscape/kra/KRAPolicy.java
    com/netscape/kra/TransportKeyUnit.java
    com/netscape/kra/StorageKeyUnit.java
    com/netscape/kra/ArchiveOptions.java
)


# set classpath
set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
    ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
    ${LDAPJDK_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR})


# set version
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})


# build pki-kra.jar
add_jar(pki-kra ${pki-kra_java_SRCS})
add_dependencies(pki-kra osutil symkey pki-nsutil pki-cmsutil pki-certsrv pki-cms pki-cmscore)
install_jar(pki-kra ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_KRA_JAR ${pki-kra_JAR_FILE} CACHE INTERNAL "pki-kra jar file")


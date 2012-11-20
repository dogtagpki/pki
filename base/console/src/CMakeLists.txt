project(pki-console_java NONE)

# '/usr/share/java/pki' jars
find_file(PKI_NSUTIL_JAR
    NAMES
        pki-nsutil.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java/pki
)

find_file(PKI_CERTSRV_JAR
    NAMES
        pki-certsrv.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java/pki
)


# '/usr/share/java' jars
find_file(BASE_JAR
    NAMES
        idm-console-base.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(MMC_JAR
    NAMES
        idm-console-mcc.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(MMC_EN_JAR
    NAMES
        idm-console-mcc_en.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(NMCLF_JAR
    NAMES
        idm-console-nmclf.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(NMCLF_EN_JAR
    NAMES
        idm-console-nmclf_en.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)


# '${JAVA_LIB_INSTALL_DIR}' jars
find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

# build console classes
javac(pki-console-classes
    SOURCES
        com/netscape/admin/certsrv/*.java
    CLASSPATH
        ${CMAKE_BINARY_DIR}/classes
        ${BASE_JAR} ${LDAPJDK_JAR} ${MMC_JAR}
        ${MMC_EN_JAR} ${NMCLF_JAR} ${NMCLF_EN_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CERTSRV_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-console.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-console.mf
)

# package console classes and resources
jar(pki-console-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-console.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-console.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/admin/certsrv/*.class
    INPUT_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}
    FILES
        com/netscape/admin/certsrv/images/*.gif
    DEPENDS
        pki-console-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-console.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CONSOLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-console.jar CACHE INTERNAL "pki-console jar file")


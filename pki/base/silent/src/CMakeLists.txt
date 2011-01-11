project(pki-silent_java Java)

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

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

set(pki-silent_java_SRCS
    common/AutoInstaller.java
    common/CMSConfig.java
    common/ParseXML.java
    common/ServerInfo.java
    common/CMSTask.java
    common/TestClient.java
    common/Certificate_Record.java
    common/ComCrypto.java
    common/CMSLDAP.java
    common/createinstance.java
    common/Utilities.java
    common/BaseState.java
    common/PostQuery.java
    common/Con2Agent.java
    common/CMSProperties.java
    common/CMSInstance.java
    argparser/IntHolder.java
    argparser/StringScanException.java
    argparser/StringHolder.java
    argparser/CharHolder.java
    argparser/ArgParser.java
    argparser/FloatHolder.java
    argparser/BooleanHolder.java
    argparser/StringScanner.java
    argparser/ObjectHolder.java
    argparser/SimpleExample.java
    argparser/ArgParserTest.java
    argparser/DoubleHolder.java
    argparser/ArgParseException.java
    argparser/LongHolder.java
    tps/ConfigureTPS.java
    ra/ConfigureRA.java
    subca/ConfigureSubCA.java
    http/HTTPResponse.java
    http/HTTPClient.java
    http/HTMLDocument.java
    http/CertSelection.java
    tks/ConfigureTKS.java
    ca/DirEnroll.java
    ca/UserEnroll.java
    ca/Request.java
    ca/checkRequest.java
    ca/ConfigureCA.java
    drm/ConfigureDRM.java
    ocsp/ConfigureOCSP.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
    ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
    ${LDAPJDK_JAR} ${XERCES_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR})

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(pki-silent ${pki-silent_java_SRCS})
add_dependencies(pki-silent osutil symkey pki-cmsutil pki-nsutil pki-certsrv pki-cms)
install_jar(pki-silent ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_SILENT_JAR ${pki-silent_JAR_FILE} CACHE INTERNAL "pki-silent jar file")

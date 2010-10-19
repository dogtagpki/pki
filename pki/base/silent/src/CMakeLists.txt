project(silent_java Java)

set(SILENT_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/cmstool.dir/" PARENT_SCOPE)
set(SILENT_JAR "${CMAKE_CURRENT_BINARY_DIR}/silent.jar" CACHE INTERNAL "silent jar file")

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

set(silent_java_SRCS
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
    ${JSS_JAR} ${LDAPJDK_JAR} ${XERCES_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR}
    ${CERTSRV_JAR} ${CMS_JAR} ${CMSUTIL_JAR} ${NSUTIL_JAR})

add_jar(silent ${silent_java_SRCS})
add_dependencies(silent osutil symkey certsrv cms cmsutil nsutil)

install(
    FILES
        ${SILENT_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

project(pki-silent_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
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

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

set(pki-silent_java_SRCS
     com/netscape/pkisilent/ConfigureTKS.java
     com/netscape/pkisilent/ConfigureCA.java
     com/netscape/pkisilent/argparser/CharHolder.java
     com/netscape/pkisilent/argparser/ArgParseException.java
     com/netscape/pkisilent/argparser/StringHolder.java
     com/netscape/pkisilent/argparser/SimpleExample.java
     com/netscape/pkisilent/argparser/ArgParser.java
     com/netscape/pkisilent/argparser/DoubleHolder.java
     com/netscape/pkisilent/argparser/ObjectHolder.java
     com/netscape/pkisilent/argparser/FloatHolder.java
     com/netscape/pkisilent/argparser/BooleanHolder.java
     com/netscape/pkisilent/argparser/StringScanException.java
     com/netscape/pkisilent/argparser/StringScanner.java
     com/netscape/pkisilent/argparser/LongHolder.java
     com/netscape/pkisilent/argparser/IntHolder.java
     com/netscape/pkisilent/ConfigureTPS.java
     com/netscape/pkisilent/http/HTTPClient.java
     com/netscape/pkisilent/http/HTMLDocument.java
     com/netscape/pkisilent/http/HTTPResponse.java
     com/netscape/pkisilent/http/CertSelection.java
     com/netscape/pkisilent/common/Request.java
     com/netscape/pkisilent/common/CertificateRecord.java
     com/netscape/pkisilent/common/Utilities.java
     com/netscape/pkisilent/common/ComCrypto.java
     com/netscape/pkisilent/common/BaseState.java
     com/netscape/pkisilent/common/CMSLDAP.java
     com/netscape/pkisilent/common/CMSConfig.java
     com/netscape/pkisilent/common/PostQuery.java
     com/netscape/pkisilent/common/ServerInfo.java
     com/netscape/pkisilent/common/UserEnroll.java
     com/netscape/pkisilent/common/ParseXML.java
     com/netscape/pkisilent/common/CMSProperties.java
     com/netscape/pkisilent/common/DirEnroll.java
     com/netscape/pkisilent/common/Con2Agent.java
     com/netscape/pkisilent/common/TestClient.java
     com/netscape/pkisilent/common/CMSTask.java
     com/netscape/pkisilent/ConfigureOCSP.java
     com/netscape/pkisilent/ConfigureRA.java
     com/netscape/pkisilent/ConfigureSubCA.java
     com/netscape/pkisilent/ConfigureDRM.java
     com/netscape/pkisilent/PKISilent.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
    ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
    ${LDAPJDK_JAR} ${XERCES_JAR}
    ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR})

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(pki-silent ${pki-silent_java_SRCS})
add_dependencies(pki-silent symkey pki-cmsutil pki-nsutil pki-certsrv pki-cms)
install_jar(pki-silent ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_SILENT_JAR ${pki-silent_JAR_FILE} CACHE INTERNAL "pki-silent jar file")

project(pki-tools_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

find_file(OSUTIL_JAR
    NAMES
        osutil.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
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

set(pki-tools_java_SRCS
    com/netscape/cmstools/PrettyPrintCrl.java
    com/netscape/cmstools/BtoA.java
    com/netscape/cmstools/PasswordCache.java
    com/netscape/cmstools/OCSPClient.java
    com/netscape/cmstools/PKCS12Export.java
    com/netscape/cmstools/TestCRLSigning.java
    com/netscape/cmstools/CRMFPopClient.java
    com/netscape/cmstools/AuditVerify.java
    com/netscape/cmstools/PrettyPrintCert.java
    com/netscape/cmstools/HttpClient.java
    com/netscape/cmstools/GenExtKeyUsage.java
    com/netscape/cmstools/CMCRevoke.java
    com/netscape/cmstools/TokenInfo.java
    com/netscape/cmstools/CMCEnroll.java
    com/netscape/cmstools/ExtJoiner.java
    com/netscape/cmstools/CMCRequest.java
    com/netscape/cmstools/AtoB.java
    com/netscape/cmstools/GenIssuerAltNameExt.java
    com/netscape/cmstools/GenSubjectAltNameExt.java
    com/netscape/cmstools/CMCResponse.java
    com/netscape/cmstools/PKCS10Client.java
    com/netscape/cmstools/DRMTool.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
    ${XALAN_JAR} ${XERCES_JAR}
    ${JSS_JAR} ${OSUTIL_JAR})

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

# build pki-tools
add_jar(pki-tools ${pki-tools_java_SRCS})
add_dependencies(pki-tools osutil pki-nsutil pki-cmsutil)
install_jar(pki-tools ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_TOOLS_JAR ${pki-tools_JAR_FILE} CACHE INTERNAL "pki-tools jar file")

create_javadoc(pki-java-tools-${APPLICATION_VERSION}
    FILES ${pki-tools_java_SRCS}
    CLASSPATH ${CMAKE_JAVA_INCLUDE_PATH}
    WINDOWTITLE "pki-java-tools"
    DOCTITLE "<h1>pki-java-tools</h1>"
    AUTHOR TRUE
    USE TRUE
    VERSION TRUE
)
add_dependencies(pki-java-tools-${APPLICATION_VERSION}_javadoc pki-tools)

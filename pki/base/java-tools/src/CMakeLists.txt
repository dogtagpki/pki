project(cmstools_java Java)

set(CMSTOOLS_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/cmstool.dir/" PARENT_SCOPE)
set(CMSTOOLS_JAR "${CMAKE_CURRENT_BINARY_DIR}/cmstools.jar" CACHE INTERNAL "cmstools jar file")

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        /usr/lib/java
        /usr/share/java
)

set(cmstools_java_SRCS
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
)

set(CMAKE_JAVA_INCLUDE_PATH ${JSS_JAR} ${OSUTIL_JAR} ${NSUTIL_JAR} ${CMSUTIL_JAR} ${CMS_JAR})

add_jar(cmstools ${netscape_java_SRCS} ${cmstools_java_SRCS})
add_dependencies(cmstools osutil nsutil cmsutil cms)

install(
    FILES
        ${CMSTOOLS_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

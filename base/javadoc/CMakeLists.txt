project(pki-javadoc)

set(doclintstr "")
if(${Java_VERSION_MINOR} VERSION_EQUAL 8 OR ${Java_VERSION_MINOR} VERSION_GREATER 8)
    set(doclintstr "-Xdoclint:none")
endif(${Java_VERSION_MINOR} VERSION_EQUAL 8 OR ${Java_VERSION_MINOR} VERSION_GREATER 8)

javadoc(pki-javadoc
    SOURCEPATH
        ${CMAKE_SOURCE_DIR}/base/util/src
        ${CMAKE_SOURCE_DIR}/base/common/src
        ${CMAKE_SOURCE_DIR}/base/java-tools/src
        ${CMAKE_SOURCE_DIR}/base/server/cms/src
    DEST
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-${APPLICATION_VERSION}
    SUBPACKAGES
        com.netscape.certsrv
        com.netscape.cms
        com.netscape.cmstools
        com.netscape.cmsutil
        org.dogtagpki
    CLASSPATH
        ${XALAN_JAR} ${XERCES_JAR}
        ${APACHE_COMMONS_CLI_JAR} ${APACHE_COMMONS_LANG_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR} ${COMMONS_IO_JAR}
        ${LDAPJDK_JAR} ${VELOCITY_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR} ${RESTEASY_CLIENT_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_TOMCAT_JAR} ${PKI_CMS_JAR} ${PKI_TOOLS_JAR}
        ${NUXWDOG_JAR}
    OPTIONS
        -windowtitle 'pki-javadoc'
        -doctitle '<h1>PKI Javadoc</h1>'
        -author
        -use
        -version
        ${doclintstr}
    DEPENDS
        pki-cmsutil-jar pki-certsrv-jar pki-tomcat-jar pki-cms-jar pki-tools-jar
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-${APPLICATION_VERSION}
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/javadoc
)

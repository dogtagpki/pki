project(pki-certsrv_java Java)

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

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_HTTPCLIENT_JAR
    NAMES
        commons-httpclient.jar
    PATHS
        /usr/share/java
)

find_file(APACHE_COMMONS_LANG_JAR
    NAMES
        apache-commons-lang.jar
    PATHS
        /usr/share/java
)

find_file(TOMCAT_CATALINA_JAR
    NAMES
        catalina.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(TOMCAT_UTIL_JAR
    NAMES
        tomcat-util.jar
    PATHS
        /usr/share/java/tomcat
)

find_file(SERVLET_JAR
    NAMES
        servlet.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(VELOCITY_JAR
    NAMES
        velocity.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
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

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(HTTPCLIENT_JAR
    NAMES
        httpclient.jar
    PATHS
        /usr/share/java/httpcomponents
)

find_file(HTTPCORE_JAR
    NAMES
        httpcore.jar
    PATHS
        /usr/share/java/httpcomponents
)

# build pki-certsrv
javac(pki-certsrv-classes
    SOURCES
        com/netscape/certsrv/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR}
        ${APACHE_COMMONS_LANG_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil pki-cmsutil
)

jar(pki-certsrv-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/certsrv/*.class
    DEPENDS
        pki-certsrv-classes
)

link(pki-certsrv
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
    DEST
        pki-certsrv-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-certsrv-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CERTSRV_JAR ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar CACHE INTERNAL "pki-certsrv jar file")


# build pki-cms
javac(pki-cms-classes
    SOURCES
        com/netscape/cms/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR}
        ${APACHE_COMMONS_LANG_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil pki-cmsutil pki-certsrv
)

jar(pki-cms-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cms-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cms/*.class
    DEPENDS
        pki-cms-classes
)

link(pki-cms
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    DEST
        pki-cms-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-cms-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
        ${CMAKE_BINARY_DIR}/dist/pki-cms-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMS_JAR ${CMAKE_BINARY_DIR}/dist/pki-cms.jar CACHE INTERNAL "pki-cms jar file")

if(WITH_JAVADOC)
    javadoc(pki-common-javadoc
        DEST
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-common-${APPLICATION_VERSION}
        SUBPACKAGES
            com.netscape.certsrv
            com.netscape.cms
        CLASSPATH
            ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
            ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
            ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR}
            ${APACHE_COMMONS_LANG_JAR}
            ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
            ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
            ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        OPTIONS
            -windowtitle 'pki-common'
            -doctitle '<h1>pki-common</h1>'
            -author
            -use
            -version
        DEPENDS
            pki-cms pki-certsrv
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-common-${APPLICATION_VERSION}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/javadoc
    )
endif(WITH_JAVADOC)


# build pki-cmscore
javac(pki-cmscore-classes
    SOURCES
        com/netscape/cmscore/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR}
        ${APACHE_COMMONS_LANG_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil pki-cmsutil pki-certsrv pki-cms
)

jar(pki-cmscore-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmscore/*.class
    DEPENDS
        pki-cmscore-classes
)

link(pki-cmscore
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
    DEST
        pki-cmscore-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-cmscore-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSCORE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar CACHE INTERNAL "pki-cmscore jar file")


# build pki-cmsbundle
jar(pki-cmsbundle-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle-${APPLICATION_VERSION}.jar
    FILES
        LogMessages.properties
        UserMessages.properties
    DEPENDS
        pki-cmsbundle-jar
)

link(pki-cmsbundle
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
    DEST
        pki-cmsbundle-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-cmsbundle-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSBUNDLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar INTERNAL "pki-cmsbundle jar file")

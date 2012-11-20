project(pki-certsrv_java NONE)

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
        pki-nsutil-jar pki-cmsutil-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-certsrv.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-certsrv.mf
)

jar(pki-certsrv-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-certsrv.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/certsrv/*.class
    DEPENDS
        pki-certsrv-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CERTSRV_JAR ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar CACHE INTERNAL "pki-certsrv jar file")


# build pki-cms
javac(pki-cms-classes
    SOURCES
        com/netscape/cms/*.java
    EXCLUDE
        com/netscape/cms/tomcat/*.java
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
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cms.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cms.mf
)

jar(pki-cms-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cms.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cms/*.class
    EXCLUDE
        com/netscape/cms/tomcat/*.class
    DEPENDS
        pki-cms-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMS_JAR ${CMAKE_BINARY_DIR}/dist/pki-cms.jar CACHE INTERNAL "pki-cms jar file")


# build pki-tomcat
javac(pki-tomcat-classes
    SOURCES
        com/netscape/cms/tomcat/*.java
    CLASSPATH
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-cms-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-tomcat.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-tomcat.mf
)

jar(pki-tomcat-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-tomcat.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cms/tomcat/*.class
    DEPENDS
        pki-tomcat-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TOMCAT_JAR ${CMAKE_BINARY_DIR}/dist/pki-tomcat.jar CACHE INTERNAL "pki-tomcat jar file")


# build pki-cmscore
javac(pki-cmscore-classes
    SOURCES
        com/netscape/cmscore/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${PKI_TOMCAT_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR}
        ${APACHE_COMMONS_LANG_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar pki-tomcat-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cmscore.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cmscore.mf
)

jar(pki-cmscore-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cmscore.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmscore/*.class
    DEPENDS
        pki-cmscore-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSCORE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar CACHE INTERNAL "pki-cmscore jar file")


# build pki-cmsbundle
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cmsbundle.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsbundle.mf
)

jar(pki-cmsbundle-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsbundle.mf
    FILES
        LogMessages.properties
        UserMessages.properties
    DEPENDS
        pki-cmsbundle-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSBUNDLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar INTERNAL "pki-cmsbundle jar file")

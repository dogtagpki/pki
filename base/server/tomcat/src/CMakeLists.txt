project(pki-tomcat)

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

find_file(TOMCAT_UTIL_SCAN_JAR
    NAMES
        tomcat-util-scan.jar
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

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
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

find_file(TOMCATJSS_JAR
    NAMES
        tomcatjss.jar
    PATHS
        /usr/share/java
)

find_file(NUXWDOG_JAR
    NAMES
        nuxwdog.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

# build pki-tomcat
javac(pki-tomcat-classes
    SOURCES
        com/netscape/cms/tomcat/*.java
    CLASSPATH
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_SCAN_JAR}
		${NUXWDOG_JAR} ${APACHE_COMMONS_LANG_JAR} ${TOMCATJSS_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/../../tomcat
)

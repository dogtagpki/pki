project(pki-tomcat)

# build pki-tomcat
javac(pki-tomcat-classes
    SOURCES
        *.java
    CLASSPATH
        ${SERVLET_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_COYOTE_JAR} ${TOMCAT_UTIL_SCAN_JAR}
        ${NUXWDOG_JAR} ${APACHE_COMMONS_LANG_JAR} ${TOMCATJSS_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/../../tomcat
    DEPENDS
        pki-tools-jar
)

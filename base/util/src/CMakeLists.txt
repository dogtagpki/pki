project(pki-cmsutil_java Java)

find_file(APACHE_COMMONS_LANG_JAR
    NAMES
        apache-commons-lang.jar
    PATHS
        /usr/share/java
)

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

# build pki-nsutil
javac(pki-nsutil-classes
    SOURCES
        netscape/*.java
    CLASSPATH
        ${APACHE_COMMONS_LANG_JAR} ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
)

jar(pki-nsutil-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-nsutil-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        netscape/*.class
    DEPENDS
        pki-nsutil-classes
)

link(pki-nsutil
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-nsutil.jar
    DEST
        pki-nsutil-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-nsutil-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-nsutil.jar
        ${CMAKE_BINARY_DIR}/dist/pki-nsutil-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_NSUTIL_JAR ${CMAKE_BINARY_DIR}/dist/pki-nsutil.jar CACHE INTERNAL "pki-nsutil jar file")


# build pki-cmsutil
javac(pki-cmsutil-classes
    SOURCES
        com/netscape/cmsutil/*.java
    CLASSPATH
        ${APACHE_COMMONS_LANG_JAR} ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil
)

jar(pki-cmsutil-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmsutil/*.class
    DEPENDS
        pki-cmsutil-classes
)

link(pki-cmsutil
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar
    DEST
        pki-cmsutil-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-cmsutil-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSUTIL_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar CACHE INTERNAL "pki-cmsutil jar file")

if(WITH_JAVADOC)
    javadoc(pki-util-javadoc
        DEST
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-util-${APPLICATION_VERSION}
        SUBPACKAGES
            com.netscape.cmsutil
        CLASSPATH
            ${APACHE_COMMONS_LANG_JAR} ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
            ${JSS_JAR} ${COMMONS_CODEC_JAR}
        OPTIONS
            -windowtitle 'pki-util'
            -doctitle '<h1>dogtag</h1>'
            -author
            -use
            -version
        DEPENDS
            pki-cmsutil
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-util-${APPLICATION_VERSION}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/javadoc
    )
endif(WITH_JAVADOC)

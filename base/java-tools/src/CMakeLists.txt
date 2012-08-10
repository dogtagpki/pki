project(pki-tools_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
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

# build pki-tools
javac(pki-tools-classes
    SOURCES
        com/netscape/cmstools/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil pki-cmsutil
)

jar(pki-tools-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tools-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmstools/*.class
    DEPENDS
        pki-tools-classes
)

link(pki-tools
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    DEST
        pki-tools-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-tools-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
        ${CMAKE_BINARY_DIR}/dist/pki-tools-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

install(
    FILES
        com/netscape/cmstools/DRMTool.cfg
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/pki/java-tools
)

set(PKI_TOOLS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tools.jar CACHE INTERNAL "pki-tools jar file")

if(WITH_JAVADOC)
    javadoc(pki-tools-javadoc
        DEST
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-java-tools-${APPLICATION_VERSION}
        SUBPACKAGES
            com.netscape.cmstools
        CLASSPATH
            ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
            ${XALAN_JAR} ${XERCES_JAR}
            ${JSS_JAR} ${COMMONS_CODEC_JAR}
        OPTIONS
            -windowtitle 'pki-java-tools'
            -doctitle '<h1>pki-java-tools</h1>'
            -author
            -use
            -version
        DEPENDS
            pki-tools
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-java-tools-${APPLICATION_VERSION}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/javadoc
    )
endif(WITH_JAVADOC)

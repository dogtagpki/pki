project(pki-cmsutil_java NONE)

# build pki-cmsutil
javac(pki-cmsutil-classes
    SOURCES
        *.java
    CLASSPATH
        ${COMMONS_LANG_JAR} ${HTTPCORE_JAR} ${HTTPCLIENT_JAR}
        ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cmsutil.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsutil.mf
)

jar(pki-cmsutil-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsutil.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    FILES
        *.class
    DEPENDS
        pki-cmsutil-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSUTIL_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar CACHE INTERNAL "pki-cmsutil jar file")

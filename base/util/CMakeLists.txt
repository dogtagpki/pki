project(util NONE)

javac(pki-cmsutil-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${COMMONS_LANG3_JAR} ${HTTPCORE_JAR} ${HTTPCLIENT_JAR}
        ${LDAPJDK_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/src/main/resources/META-INF/MANIFEST.MF
)

jar(pki-cmsutil-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsutil.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/src/main/resources/META-INF/MANIFEST.MF
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

javac(pki-util-test-classes
    SOURCES
        src/test/java/*.java
    CLASSPATH
        ${PKI_CMSUTIL_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${HAMCREST_JAR} ${JUNIT_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/test/classes
    DEPENDS
        pki-test-classes pki-cmsutil-jar
)

# TODO: create CMake function to find all JUnit test classes
add_junit_test(test-pki-util
    CLASSPATH
        ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
        ${PKI_CMSUTIL_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR}
        ${HAMCREST_JAR} ${JUNIT_JAR}
        ${CMAKE_BINARY_DIR}/test/classes
    TESTS
        com.netscape.cmsutil.crypto.KeyIDCodecTest
    REPORTS_DIR
        reports
    DEPENDS
        pki-util-test-classes
)

add_test(
    NAME "test_PKICertImport"
    COMMAND bash "${CMAKE_SOURCE_DIR}/base/util/src/test/shell/test_PKICertImport.bash"
)

install(
    FILES
        src/main/shell/PKICertImport.bash
    DESTINATION
        ${BIN_INSTALL_DIR}
    RENAME
        PKICertImport
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
)

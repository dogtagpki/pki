project(pki-util-test NONE)

# build pki-util-test
# TODO: build test only when the test is invoked
javac(pki-util-test-classes
    SOURCES
        *.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${HAMCREST_JAR} ${JUNIT_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/test/classes
    DEPENDS
        pki-test-classes pki-nsutil-jar pki-cmsutil-jar
)

# create test target
# do not include xalan and xerces in class path
# TODO: create CMake function to find all JUnit test classes
add_junit_test(test-pki-util
    CLASSPATH
        ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
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
    COMMAND bash "${CMAKE_SOURCE_DIR}/base/util/test/PKICertImport/runtest.bash"
)

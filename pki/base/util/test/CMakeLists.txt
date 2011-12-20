project(pki-util-test Java)

# TODO: create CMake function to find all Java files
set(pki-util-test_SRCS
    com/netscape/security/util/BMPStringTest.java
    com/netscape/security/util/IA5StringTest.java
    com/netscape/security/util/JSSUtil.java
    com/netscape/security/util/PrintableStringTest.java
    com/netscape/security/util/StringTestUtil.java
    com/netscape/security/util/TeletexStringTest.java
    com/netscape/security/util/UniversalStringTest.java
    com/netscape/security/util/UTF8StringTest.java
    com/netscape/security/x509/ConverterTestUtil.java
    com/netscape/security/x509/DirStrConverterTest.java
    com/netscape/security/x509/GenericValueConverterTest.java
    com/netscape/security/x509/IA5StringConverterTest.java
    com/netscape/security/x509/PrintableConverterTest.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
    ${JSS_JAR} ${LDAPJDK_JAR} ${OSUTIL_JAR} ${XALAN_JAR} ${XERCES_JAR}
    ${PKI_TEST_JAR} ${JUNIT_JAR}
)

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

# build test jar file
# TODO: create CMake function to compile without building jar file
# TODO: build test only when the test is invoked
set(CMAKE_JAR_CLASSES_PREFIX com/netscape)
add_jar(pki-util-test ${pki-util-test_SRCS})
add_dependencies(pki-util-test osutil pki-nsutil pki-cmsutil pki-test)

# create test target
# do not include xalan and xerces in class path
# TODO: create CMake function to find all JUnit test classes
add_junit_test(test-pki-util
    CLASSPATH
        ${pki-util-test_JAR_FILE}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${OSUTIL_JAR}
        ${PKI_TEST_JAR} ${JUNIT_JAR}
    TESTS
        com.netscape.security.util.BMPStringTest
        com.netscape.security.util.IA5StringTest
        com.netscape.security.util.PrintableStringTest
        com.netscape.security.util.TeletexStringTest
        com.netscape.security.util.UniversalStringTest
        com.netscape.security.util.UTF8StringTest
        com.netscape.security.x509.DirStrConverterTest
        com.netscape.security.x509.GenericValueConverterTest
        com.netscape.security.x509.IA5StringConverterTest
        com.netscape.security.x509.PrintableConverterTest
    REPORTS_DIR
        reports
)

# include test into the main test
add_dependencies(test test-pki-util)

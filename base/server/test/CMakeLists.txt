project(pki-server-test NONE)

# build pki-server-test
# TODO: build test only when the test is invoked
javac(pki-server-test-classes
    SOURCES
        *.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR}
        ${HAMCREST_JAR} ${JUNIT_JAR} ${COMMONS_IO_JAR}
        ${CMAKE_BINARY_DIR}/test/classes
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/test/classes
    DEPENDS
        pki-test-classes
        pki-nsutil-jar pki-cmsutil-jar
        pki-certsrv-jar pki-cms-jar pki-cmscore-jar pki-cmsbundle-jar
)

# create test target
# do not include xalan and xerces in class path
# TODO: create CMake function to find all JUnit test classes
add_junit_test(test-pki-server
    CLASSPATH
        ${SLF4J_API_JAR} ${SLF4J_SIMPLE_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${HAMCREST_JAR} ${JUNIT_JAR} ${COMMONS_IO_JAR}
        ${CMAKE_BINARY_DIR}/test/classes
    TESTS
        com.netscape.cmscore.authentication.AuthTokenTest
        com.netscape.cmscore.dbs.CertRecordListTest
        com.netscape.cmscore.dbs.DBRegistryTest
        # com.netscape.cmscore.request.AgentApprovalsTest
        com.netscape.cmscore.request.ExtAttrDynMapperTest
        com.netscape.cmscore.request.ExtDataHashtableTest
        com.netscape.cmscore.request.RequestQueueTest
        com.netscape.cmscore.request.RequestRecordTest
        # com.netscape.cmscore.request.RequestTest
        com.netscape.cmscore.password.PlainPasswordFileTest
    REPORTS_DIR
        reports
    DEPENDS
        pki-server-test-classes
)

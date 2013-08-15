project(pki-server-test NONE)

find_file(PKI_CERTSRV_JAR
    NAMES
		pki-certsrv.jar
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMS_JAR
    NAMES
		pki-cms.jar
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMSCORE_JAR
    NAMES
		pki-cmscore.jar
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMSBUNDLE_JAR
    NAMES
		pki-cmsbundle.jar
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

# build pki-server-test
# TODO: build test only when the test is invoked
javac(pki-server-test-classes
    SOURCES
        com/netscape/cmscore/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR} ${JUNIT_JAR}
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
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR} ${JUNIT_JAR}
        ${CMAKE_BINARY_DIR}/test/classes
    TESTS
        com.netscape.cmscore.authentication.AuthTokenTest
        com.netscape.cmscore.dbs.CertRecordListTest
        com.netscape.cmscore.dbs.DBRegistryTest
        com.netscape.cmscore.request.AgentApprovalsTest
        com.netscape.cmscore.request.ExtAttrDynMapperTest
        com.netscape.cmscore.request.ExtDataHashtableTest
        com.netscape.cmscore.request.RequestQueueTest
        com.netscape.cmscore.request.RequestRecordTest
        com.netscape.cmscore.request.RequestTest
    REPORTS_DIR
        reports
)

# include test into the main test
add_dependencies(test test-pki-server)

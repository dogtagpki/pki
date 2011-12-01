project(pki-common-test Java)

find_file(PKI_CERTSRV_JAR
    NAMES
		pki-certsrv.jar
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMS_JAR
    NAMES
		pki-cms
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMSCORE_JAR
    NAMES
		pki-cmscore
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

find_file(PKI_CMSBUNDLE_JAR
    NAMES
		pki-cmsbundle
    PATHS
        ${JAVA_JAR_INSTALL_DIR}/pki
)

# TODO: create CMake function to find all Java files
set(pki-common-test_SRCS
    com/netscape/certsrv/app/CMSEngineDefaultStub.java
    com/netscape/certsrv/authentication/AuthTokenTest.java
    com/netscape/certsrv/logging/LoggerDefaultStub.java
    com/netscape/certsrv/request/AgentApprovalsTest.java
    com/netscape/cmscore/dbs/CertRecordListTest.java
    com/netscape/cmscore/dbs/DBRegistryDefaultStub.java
    com/netscape/cmscore/dbs/DBRegistryTest.java
    com/netscape/cmscore/dbs/DBSSessionDefaultStub.java
    com/netscape/cmscore/dbs/DBSubsystemDefaultStub.java
    com/netscape/cmscore/dbs/DBVirtualListDefaultStub.java
    com/netscape/cmscore/dbs/RequestRecordDefaultStub.java
    com/netscape/cmscore/request/DBDynAttrMapperDefaultStub.java
    com/netscape/cmscore/request/ExtAttrDynMapperTest.java
    com/netscape/cmscore/request/ExtDataHashtableTest.java
    com/netscape/cmscore/request/RequestDefaultStub.java
    com/netscape/cmscore/request/RequestModDefaultStub.java
    com/netscape/cmscore/request/RequestQueueTest.java
    com/netscape/cmscore/request/RequestRecordTest.java
    com/netscape/cmscore/request/RequestTest.java
    com/netscape/cmscore/test/CMSBaseTestCase.java
    com/netscape/cmscore/test/TestHelper.java
    com/netscape/test/TestListener.java
    com/netscape/test/TestRunner.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
    ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
    ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
    ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR} ${JUNIT_JAR}
)

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

# build test jar file
# TODO: create CMake function to compile without building jar file
# TODO: build test only when the test is invoked
set(CMAKE_JAR_CLASSES_PREFIX com/netscape)
add_jar(pki-common-test ${pki-common-test_SRCS})
add_dependencies(pki-common-test
    osutil pki-nsutil pki-cmsutil
    pki-certsrv pki-cms pki-cmscore pki-cmsbundle
)

# create test target
# do not include xalan and xerces in class path
# TODO: create CMake function to find all JUnit test classes
add_junit_test(test-pki-common
    CLASSPATH
        ${pki-common-test_JAR_FILE}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR} ${PKI_CMSBUNDLE_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR}
        ${JSS_JAR} ${OSUTIL_JAR} ${SYMKEY_JAR} ${JUNIT_JAR}
    TESTS
        com.netscape.certsrv.authentication.AuthTokenTest
        com.netscape.certsrv.request.AgentApprovalsTest
        com.netscape.cmscore.dbs.CertRecordListTest
        com.netscape.cmscore.dbs.DBRegistryTest
        com.netscape.cmscore.request.ExtAttrDynMapperTest
        com.netscape.cmscore.request.ExtDataHashtableTest
        com.netscape.cmscore.request.RequestQueueTest
        com.netscape.cmscore.request.RequestRecordTest
        com.netscape.cmscore.request.RequestTest
    REPORTS_DIR
        reports
)

# include test into the main test
add_dependencies(test test-pki-common)

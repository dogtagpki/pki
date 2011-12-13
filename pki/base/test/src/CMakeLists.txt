project(pki-test_java Java)

# TODO: create CMake function to find all Java files
set(pki-test_java_SRCS
    com/netscape/test/TestListener.java
    com/netscape/test/TestRunner.java
)

set(CMAKE_JAVA_INCLUDE_PATH
    ${XALAN_JAR} ${XERCES_JAR} ${JUNIT_JAR}
)

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

# build test jar file
# TODO: create CMake function to compile without building jar file
# TODO: build test only when the test is invoked
set(CMAKE_JAR_CLASSES_PREFIX com/netscape)
add_jar(pki-test ${pki-test_java_SRCS})
set(PKI_TEST_JAR ${pki-test_JAR_FILE} CACHE INTERNAL "pki-test jar file")
project(pki-test_java NONE)

# build pki-test
# TODO: build test only when the test is invoked
javac(pki-test-classes
    SOURCES
        com/netscape/test/*.java
    CLASSPATH
        ${XALAN_JAR} ${XERCES_JAR} ${JUNIT_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/test/classes
)

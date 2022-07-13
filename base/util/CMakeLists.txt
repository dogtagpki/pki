project(util NONE)

javac(pki-cmsutil-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${COMMONS_LANG3_JAR} ${HTTPCORE_JAR} ${HTTPCLIENT_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${JAXB_API_JAR}
        ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${SLF4J_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
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

if(RUN_TESTS)
    javac(pki-util-test-classes
        SOURCES
            src/test/java/*.java
        CLASSPATH
            ${PKI_CMSUTIL_JAR}
            ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR}
            ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
            ${HAMCREST_JAR} ${JUNIT_JAR}
        OUTPUT_DIR
            ${CMAKE_BINARY_DIR}/test/classes
        DEPENDS
            pki-cmsutil-jar
    )

    execute_process(
        COMMAND bash "-c"
        "grep -ilR @Test ${PROJECT_SOURCE_DIR} \
        | cut -d':' -f1 \
        | awk -F '/src/test/java/' '{ print $2 }' \
        | sed 's/.java/;/g' \
        | sed 's!/!.!g' \
        | tr -d '\n'"
        OUTPUT_VARIABLE DISCOVERED_TESTS
    )

    add_junit_test(test-pki-util
        CLASSPATH
            ${SLF4J_API_JAR} ${SLF4J_JDK14_JAR}
            ${PKI_CMSUTIL_JAR}
            ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR}
            ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
            ${HAMCREST_JAR} ${JUNIT_JAR}
            ${CMAKE_BINARY_DIR}/test/classes
        TESTS
            ${DISCOVERED_TESTS}
        REPORTS_DIR
            reports
        DEPENDS
            pki-util-test-classes
    )
endif(RUN_TESTS)

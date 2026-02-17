project(server-core)

# build server-core classes
javac(pki-server-core-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${JSS_JAR}
        ${PKI_COMMON_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-jar
)

add_dependencies(java pki-server-core-classes)

set(PKI_SERVER_CORE_JAR ${CMAKE_BINARY_DIR}/dist/pki-server-core.jar
    CACHE INTERNAL "pki-server-core.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

# build pki-server-core.jar
jar(pki-server-core-jar
    CREATE
        ${PKI_SERVER_CORE_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-core-classes
)

add_dependencies(java pki-server-core-jar)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_SERVER_CORE_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

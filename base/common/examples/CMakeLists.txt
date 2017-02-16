project(examples)

javac(pki-examples-classes
    SOURCES
        java/*.java
    CLASSPATH
        ${JSS_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar
)

install(
    DIRECTORY
        java
    DESTINATION
        ${DATA_INSTALL_DIR}/examples
)

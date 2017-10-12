project(pki-cmscore)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cmscore.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cmscore.mf
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSCORE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmscore.jar CACHE INTERNAL "pki-cmscore jar file")

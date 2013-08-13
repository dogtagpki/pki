project(base)

# The order is important!
if (APPLICATION_FLAVOR_PKI_CORE)
    add_subdirectory(test)
    add_subdirectory(setup)
    add_subdirectory(symkey)
    add_subdirectory(util)
    add_subdirectory(common)
    add_subdirectory(native-tools)
    add_subdirectory(java-tools)
    add_subdirectory(server)
    if(BUILD_PKI_SELINUX)
        add_subdirectory(selinux)
    endif(BUILD_PKI_SELINUX)
    add_subdirectory(ca)
    add_subdirectory(kra)
    add_subdirectory(ocsp)
    add_subdirectory(tks)
    add_subdirectory(tps)
    add_subdirectory(silent)

    if(WITH_JAVADOC)
        add_subdirectory(javadoc)
    endif(WITH_JAVADOC)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/VERSION
        ${CMAKE_CURRENT_BINARY_DIR}/VERSION
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/VERSION
        DESTINATION
            ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}
    )

endif (APPLICATION_FLAVOR_PKI_CORE)

if (APPLICATION_FLAVOR_PKI_RA)
    add_subdirectory(ra)
endif (APPLICATION_FLAVOR_PKI_RA)

if (APPLICATION_FLAVOR_PKI_TPS)
    add_subdirectory(tps)
endif (APPLICATION_FLAVOR_PKI_TPS)

if (APPLICATION_FLAVOR_PKI_CONSOLE)
    add_subdirectory(test)
    add_subdirectory(console)
endif (APPLICATION_FLAVOR_PKI_CONSOLE)

if (APPLICATION_FLAVOR_PKI_MIGRATE)
    add_subdirectory(test)
    add_subdirectory(migrate)
endif (APPLICATION_FLAVOR_PKI_MIGRATE)

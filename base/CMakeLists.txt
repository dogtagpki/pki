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
    add_subdirectory(deploy)
    add_subdirectory(selinux)
    add_subdirectory(ca)
    add_subdirectory(kra)
    add_subdirectory(ocsp)
    add_subdirectory(tks)
    add_subdirectory(silent)

    if(WITH_JAVADOC)
        add_subdirectory(javadoc)
    endif(WITH_JAVADOC)

    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/VERSION ${APPLICATION_VERSION})

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

project(base)

# The order is important!
if (APPLICATION_FLAVOR_PKI_CORE)
    add_subdirectory(test)
    add_subdirectory(symkey)
    add_subdirectory(util)
    add_subdirectory(common)
    add_subdirectory(native-tools)
    add_subdirectory(java-tools)

    if(WITH_SERVER)
        add_subdirectory(server)
        add_subdirectory(ca)
        add_subdirectory(kra)
        add_subdirectory(ocsp)
        add_subdirectory(tks)
        add_subdirectory(tps)
        add_subdirectory(setup)
        # required for native 'tpsclient' utility
        add_subdirectory(tps-client)

        if(WITH_JAVADOC)
            add_subdirectory(javadoc)
        endif(WITH_JAVADOC)

    endif(WITH_SERVER)

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

if (APPLICATION_FLAVOR_PKI_CONSOLE)
    add_subdirectory(test)
    add_subdirectory(console)
endif (APPLICATION_FLAVOR_PKI_CONSOLE)

if (APPLICATION_FLAVOR_PKI_MIGRATE)
    add_subdirectory(test)
    add_subdirectory(migrate)
endif (APPLICATION_FLAVOR_PKI_MIGRATE)

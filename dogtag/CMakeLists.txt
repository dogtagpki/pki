project(dogtag)

if (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)
    # compute certificate system name
    set(CERTIFICATE_SYSTEM_THEME "Dogtag")
    if ("${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}" STREQUAL "10.5")
        set(CERTIFICATE_SYSTEM_VERSION "9")
    elseif ("${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}" STREQUAL "10.6")
        set(CERTIFICATE_SYSTEM_VERSION "10")
    else()
        set(CERTIFICATE_SYSTEM_VERSION "")
    endif()
    set(CERTIFICATE_SYSTEM_NAME "${CERTIFICATE_SYSTEM_THEME} Certificate System ${CERTIFICATE_SYSTEM_VERSION}")

    add_subdirectory(common-ui)
    add_subdirectory(console-ui)
endif (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)

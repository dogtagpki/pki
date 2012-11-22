project(dogtag)

if (APPLICATION_FLAVOR_IPA_PKI_THEME)
    add_subdirectory(common-ui)
endif (APPLICATION_FLAVOR_IPA_PKI_THEME)
if (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)
    add_subdirectory(common-ui)
    add_subdirectory(console-ui)
endif (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)

project(dogtag)

if (BUILD_DOGTAG_PKI_THEME)
    add_subdirectory(common-ui)
    add_subdirectory(console-ui)
endif (BUILD_DOGTAG_PKI_THEME)

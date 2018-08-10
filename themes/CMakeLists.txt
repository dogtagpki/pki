project(themes)

if (BUILD_DOGTAG_PKI_THEME)
    add_subdirectory(dogtag)
elseif (BUILD_REDHAT_PKI_THEME)
    add_subdirectory(redhat)
endif ()

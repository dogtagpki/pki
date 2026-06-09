project(dogtag)

set(CERTIFICATE_SYSTEM_THEME "Dogtag")
set(CERTIFICATE_SYSTEM_NAME "${CERTIFICATE_SYSTEM_THEME} Certificate System")
set(CERTIFICATE_SYSTEM_VERSION "${PRODUCT_VERSION}")

if(WITH_SERVER)
    add_subdirectory(common-ui)
endif(WITH_SERVER)

if(WITH_CONSOLE)
    add_subdirectory(console-ui)
endif(WITH_CONSOLE)

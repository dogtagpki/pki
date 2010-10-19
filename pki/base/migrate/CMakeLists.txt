project(migrate)

set(INSTALL_DIRS
    41ToTxt
    42SP2ToTxt
    42ToTxt
    45ToTxt
    47ToTxt
    60ToTxt
    61ToTxt
    62ToTxt
    63ToTxt
    70ToTxt
    71ToTxt
    72ToTxt
    73ToTxt
    80
    TpsTo80
    TxtTo60
    TxtTo61
    TxtTo62
    TxtTo70
    TxtTo71
    TxtTo72
    TxtTo73
    TxtTo80
)

foreach(INSTALL_DIR ${INSTALL_DIRS})
    install(
        DIRECTORY
            ${INSTALL_DIR}
        DESTINATION
            ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/${INSTALL_DIR}
    )
endforeach(INSTALL_DIR ${INSTALL_DIRS})

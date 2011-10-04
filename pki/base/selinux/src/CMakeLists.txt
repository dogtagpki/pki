set(POLICY_MAKEFILE /usr/share/selinux/devel/Makefile)

set(policy_SRCS
    pki.fc
    pki.if
    pki.te
)

if (LINUX)
    if (EXISTS ${POLICY_MAKEFILE})
        foreach(_POLICY ${policy_SRCS})
            macro_copy_file(${CMAKE_CURRENT_SOURCE_DIR}/${_POLICY} ${CMAKE_CURRENT_BINARY_DIR}/${_POLICY})
        endforeach(_POLICY ${policy_SRCS})

        # FIXME This should be done by cmake
        add_custom_target(selinux ALL
            COMMAND ${CMAKE_BUILD_TOOL} -f ${POLICY_MAKEFILE}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )

        install(
            FILES
                ${CMAKE_CURRENT_BINARY_DIR}/pki.pp
            DESTINATION
                ${SHARE_INSTALL_PREFIX}/selinux/modules
        )
    endif (EXISTS ${POLICY_MAKEFILE})
endif (LINUX)

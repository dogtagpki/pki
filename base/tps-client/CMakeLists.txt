project(tps CXX)

# NOTE:  TPS utilizes internal libraries located under '%{_libdir}/tps'.
#
#        One method of resolving this issue is the use of RPATH as
#        described in 'http://www.cmake.org/Wiki/CMake_RPATH_handling'.
#
#        While Fedora allows the use of RPATH for this purpose as documented
#        in the section entitled 'Rpath_for_Internal_Libraries' in the URL
#        called 'http://fedoraproject.org/wiki/Packaging/Guidelines',
#        the RPM '%cmake' macro overrides use of RPATH on Fedora and RHEL.
#
#        To resolve this issue on Fedora and RHEL, one of the following
#        methods may be utilized:
#
#        (1) Uncomment the 'SET(CMAKE_SKIP_RPATH  FALSE)' line below, or
#        (2) Implement the files described in the section entitled
#            'Alternatives to Rpath' in the URL called
#            'http://fedoraproject.org/wiki/Packaging/Guidelines'.

# use, i.e. don't skip the full RPATH
# (overrides '%cmake' macro setting of true)
#SET(CMAKE_SKIP_RPATH  FALSE)

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE) 

# the RPATH to be used when installing
SET(CMAKE_INSTALL_RPATH "${LIB_INSTALL_DIR}/tps")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_subdirectory(src)
add_subdirectory(tools)

install(
    DIRECTORY
        man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

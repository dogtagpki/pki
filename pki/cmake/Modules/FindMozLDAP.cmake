# - Try to find MozLDAP
# Once done this will define
#
#  MOZLDAP_FOUND - system has MozLDAP
#  MOZLDAP_INCLUDE_DIRS - the MozLDAP include directory
#  MOZLDAP_LIBRARIES - Link these to use MozLDAP
#  MOZLDAP_DEFINITIONS - Compiler switches required for using MozLDAP
#
#  Copyright (c) 2010 Andreas Schneider <asn@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (MOZLDAP_LIBRARIES AND MOZLDAP_INCLUDE_DIRS)
  # in cache already
  set(MOZLDAP_FOUND TRUE)
else (MOZLDAP_LIBRARIES AND MOZLDAP_INCLUDE_DIRS)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_MOZLDAP mozldap)
  endif (PKG_CONFIG_FOUND)

  find_path(MOZLDAP_INCLUDE_DIR
    NAMES
      ldap.h
    PATHS
      ${_MOZLDAP_INCLUDEDIR}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
    PATH_SUFFIXES
      mozldap
  )

  find_library(SSLDAP60_LIBRARY
    NAMES
      ssldap60
    PATHS
      ${_MOZLDAP_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  find_library(PRLDAP60_LIBRARY
    NAMES
      prldap60
    PATHS
      ${_MOZLDAP_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  find_library(LDAP60_LIBRARY
    NAMES
      ldap60
    PATHS
      ${_MOZLDAP_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(MOZLDAP_INCLUDE_DIRS
    ${MOZLDAP_INCLUDE_DIR}
  )

  if (SSLDAP60_LIBRARY)
    set(MOZLDAP_LIBRARIES
        ${MOZLDAP_LIBRARIES}
        ${SSLDAP60_LIBRARY}
    )
  endif (SSLDAP60_LIBRARY)

  if (PRLDAP60_LIBRARY)
    set(MOZLDAP_LIBRARIES
        ${MOZLDAP_LIBRARIES}
        ${PRLDAP60_LIBRARY}
    )
  endif (PRLDAP60_LIBRARY)

  if (LDAP60_LIBRARY)
    set(MOZLDAP_LIBRARIES
        ${MOZLDAP_LIBRARIES}
        ${LDAP60_LIBRARY}
    )
  endif (LDAP60_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(MozLDAP DEFAULT_MSG MOZLDAP_LIBRARIES MOZLDAP_INCLUDE_DIRS)

  # show the MOZLDAP_INCLUDE_DIRS and MOZLDAP_LIBRARIES variables only in the advanced view
  mark_as_advanced(MOZLDAP_INCLUDE_DIRS MOZLDAP_LIBRARIES)

endif (MOZLDAP_LIBRARIES AND MOZLDAP_INCLUDE_DIRS)

# - Try to find Ldap
# Once done this will define
#
#  LDAP_FOUND - system has Ldap
#  LDAP_INCLUDE_DIRS - the Ldap include directory
#  LDAP_LIBRARIES - Link these to use Ldap
#  LDAP_DEFINITIONS - Compiler switches required for using Ldap
#
#  Copyright (c) 2010 Matthew Harmsen <mharmsen@redhat.com>
#
#  NOTE:  This file was generated via 'generate_findpackage_file'
#
#         Copyright (c) 2006 Alexander Neundorf <neundorf@kde.org>
#         Copyright (c) 2006 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (LDAP_LIBRARIES AND LDAP_INCLUDE_DIRS)
  # in cache already
  set(LDAP_FOUND TRUE)
else (LDAP_LIBRARIES AND LDAP_INCLUDE_DIRS)

  find_path(LDAP_INCLUDE_DIR
    NAMES
      ldap.h lber.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(LDAP_LIBRARY
    NAMES
      ldap
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  find_library(LBER_LIBRARY
    NAMES
      lber
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(LDAP_INCLUDE_DIRS
    ${LDAP_INCLUDE_DIR}
  )

  if (LDAP_LIBRARY)
    set(LDAP_LIBRARIES
        ${LDAP_LIBRARIES}
        ${LDAP_LIBRARY}
    )
  endif (LDAP_LIBRARY)

  if (LBER_LIBRARY)
    set(LDAP_LIBRARIES
        ${LDAP_LIBRARIES}
        ${LBER_LIBRARY}
    )
  endif (LBER_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Ldap DEFAULT_MSG LDAP_LIBRARIES LDAP_INCLUDE_DIRS)

  # show the LDAP_INCLUDE_DIRS and LDAP_LIBRARIES variables only in the advanced view
  mark_as_advanced(LDAP_INCLUDE_DIRS LDAP_LIBRARIES)

endif (LDAP_LIBRARIES AND LDAP_INCLUDE_DIRS)


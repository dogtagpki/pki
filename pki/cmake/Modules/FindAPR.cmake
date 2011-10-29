# - Try to find APR
# Once done this will define
#
#  APR_FOUND - system has APR
#  APR_INCLUDE_DIRS - the APR include directory
#  APR_LIBRARIES - Link these to use APR
#  APR_DEFINITIONS - Compiler switches required for using APR
#
#  Copyright (c) 2010 Andreas Schneider <asn@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (APR_LIBRARIES AND APR_INCLUDE_DIRS)
  # in cache already
  set(APR_FOUND TRUE)
else (APR_LIBRARIES AND APR_INCLUDE_DIRS)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_APR apr-1)
  endif (PKG_CONFIG_FOUND)

  find_path(APR_INCLUDE_DIR
    NAMES
      apr.h
    PATHS
      ${_APR_INCLUDEDIR}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
    PATH_SUFFIXES
      apr-1
  )

  find_library(APR-1_LIBRARY
    NAMES
      apr-1
    PATHS
      ${_APR_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(APR_INCLUDE_DIRS
    ${APR_INCLUDE_DIR}
  )

  if (APR-1_LIBRARY)
    set(APR_LIBRARIES
        ${APR_LIBRARIES}
        ${APR-1_LIBRARY}
    )
  endif (APR-1_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(APR DEFAULT_MSG APR_LIBRARIES APR_INCLUDE_DIRS)

  # show the APR_INCLUDE_DIRS and APR_LIBRARIES variables only in the advanced view
  mark_as_advanced(APR_INCLUDE_DIRS APR_LIBRARIES)

endif (APR_LIBRARIES AND APR_INCLUDE_DIRS)

# - Try to find Svrcore
# Once done this will define
#
#  SVRCORE_FOUND - system has Svrcore
#  SVRCORE_INCLUDE_DIRS - the Svrcore include directory
#  SVRCORE_LIBRARIES - Link these to use Svrcore
#  SVRCORE_DEFINITIONS - Compiler switches required for using Svrcore
#
#  Copyright (c) 2010 Matthew Harmsen <mharmsen@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (SVRCORE_LIBRARIES AND SVRCORE_INCLUDE_DIRS)
  # in cache already
  set(SVRCORE_FOUND TRUE)
else (SVRCORE_LIBRARIES AND SVRCORE_INCLUDE_DIRS)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_SVRCORE svrcore)
  endif (PKG_CONFIG_FOUND)

  find_path(SVRCORE_INCLUDE_DIR
    NAMES
      svrcore.h
    PATHS
      ${_SVRCORE_INCLUDEDIR}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
    PATH_SUFFIXES
      svrcore
  )

  find_library(SVRCORE_LIBRARY
    NAMES
      svrcore
    PATHS
      ${_SVRCORE_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(SVRCORE_INCLUDE_DIRS
    ${SVRCORE_INCLUDE_DIR}
  )

  if (SVRCORE_LIBRARY)
    set(SVRCORE_LIBRARIES
        ${SVRCORE_LIBRARIES}
        ${SVRCORE_LIBRARY}
    )
  endif (SVRCORE_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Svrcore DEFAULT_MSG SVRCORE_LIBRARIES SVRCORE_INCLUDE_DIRS)

  # show the SVRCORE_INCLUDE_DIRS and SVRCORE_LIBRARIES variables only in the advanced view
  mark_as_advanced(SVRCORE_INCLUDE_DIRS SVRCORE_LIBRARIES)

endif (SVRCORE_LIBRARIES AND SVRCORE_INCLUDE_DIRS)

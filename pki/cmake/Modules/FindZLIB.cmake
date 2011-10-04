# - Try to find ZLIB
# Once done this will define
#
#  ZLIB_FOUND - system has ZLIB
#  ZLIB_INCLUDE_DIRS - the ZLIB include directory
#  ZLIB_LIBRARIES - Link these to use ZLIB
#  ZLIB_DEFINITIONS - Compiler switches required for using ZLIB
#
#  Copyright (c) 2009-2010 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)
  # in cache already
  set(ZLIB_FOUND TRUE)
else (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)
  if (WIN32)
    set(_ZLIB_DIR $ENV{PROGRAMFILES}/GnuWin32)
  endif (WIN32)

  find_path(ZLIB_INCLUDE_DIR
    NAMES
      zlib.h
    PATHS
      ${_ZLIB_DIR}/include
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      /usr/lib/sfw/include
  )

  find_library(Z_LIBRARY
    NAMES
      z
      zlib
      zlib1
    PATHS
      ${_ZLIB_DIR}/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  set(ZLIB_INCLUDE_DIRS
    ${ZLIB_INCLUDE_DIR}
  )

  if (Z_LIBRARY)
    set(ZLIB_LIBRARIES
        ${ZLIB_LIBRARIES}
        ${Z_LIBRARY}
    )
  endif (Z_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(ZLIB DEFAULT_MSG ZLIB_LIBRARIES ZLIB_INCLUDE_DIRS)

  # show the ZLIB_INCLUDE_DIRS and ZLIB_LIBRARIES variables only in the advanced view
  mark_as_advanced(ZLIB_INCLUDE_DIRS ZLIB_LIBRARIES)

endif (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)

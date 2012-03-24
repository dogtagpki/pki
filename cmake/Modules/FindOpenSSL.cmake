# - Try to find OpenSSL
# Once done this will define
#
#  OPENSSL_FOUND - system has OpenSSL
#  OPENSSL_INCLUDE_DIRS - the OpenSSL include directory
#  OPENSSL_LIBRARIES - Link these to use OpenSSL
#  OPENSSL_DEFINITIONS - Compiler switches required for using OpenSSL
#
#  Copyright (c) 2009-2010 Andreas Schneider <mail@cynapses.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (OPENSSL_LIBRARIES AND OPENSSL_INCLUDE_DIRS)
  # in cache already
  set(OPENSSL_FOUND TRUE)
else (OPENSSL_LIBRARIES AND OPENSSL_INCLUDE_DIRS)
  if (WIN32)
    set(_OPENSSL_DIR $ENV{PROGRAMFILES}/OpenSSL)
  endif (WIN32)

  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_OPENSSL openssl)
  endif (PKG_CONFIG_FOUND)

  find_path(OPENSSL_INCLUDE_DIR
    NAMES
      openssl/ssl.h
    PATHS
      ${_OPENSSL_DIR}/include
      ${_OPENSSL_INCLUDEDIR}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      /usr/lib/sfw/include
  )

  find_library(SSL_LIBRARY
    NAMES
      ssl
      libssl
    PATHS
      ${_OPENSSL_DIR}/lib
      ${_OPENSSL_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  find_library(SSLEAY32_LIBRARY
    NAMES
      ssleay32
    PATHS
      ${_OPENSSL_DIR}/lib
      ${_OPENSSL_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  find_library(SSLEAY32MD_LIBRARY
    NAMES
      ssleay32MD
    PATHS
      ${_OPENSSL_DIR}/lib
      ${_OPENSSL_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  find_library(CRYPTO_LIBRARY
    NAMES
      crypto
      libcrypto
      eay
      eay32
      libeay
      libeay32
    PATHS
      ${_OPENSSL_DIR}/lib
      ${_OPENSSL_LIBDIR}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /usr/sfw/lib/64
      /usr/sfw/lib
  )

  set(OPENSSL_INCLUDE_DIRS
    ${OPENSSL_INCLUDE_DIR}
  )

  if (SSL_LIBRARY)
    set(OPENSSL_LIBRARIES
        ${OPENSSL_LIBRARIES}
        ${SSL_LIBRARY}
    )
  endif (SSL_LIBRARY)

  if (SSLEAY32_LIBRARY)
    set(OPENSSL_LIBRARIES
        ${OPENSSL_LIBRARIES}
        ${SSLEAY32_LIBRARY}
    )
  endif (SSLEAY32_LIBRARY)

  if (SSLEAY32MD_LIBRARY)
    set(OPENSSL_LIBRARIES
        ${OPENSSL_LIBRARIES}
        ${SSLEAY32MD_LIBRARY}
    )
  endif (SSLEAY32MD_LIBRARY)

  if (CRYPTO_LIBRARY)
    set(OPENSSL_LIBRARIES
        ${OPENSSL_LIBRARIES}
        ${CRYPTO_LIBRARY}
    )
  endif (CRYPTO_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(OpenSSL DEFAULT_MSG OPENSSL_LIBRARIES OPENSSL_INCLUDE_DIRS)

  # show the OPENSSL_INCLUDE_DIRS and OPENSSL_LIBRARIES variables only in the advanced view
  mark_as_advanced(OPENSSL_INCLUDE_DIRS OPENSSL_LIBRARIES)

endif (OPENSSL_LIBRARIES AND OPENSSL_INCLUDE_DIRS)

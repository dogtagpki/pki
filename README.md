Dogtag PKI
==========

[![Build Status](https://travis-ci.org/dogtagpki/pki-nightly-test.svg?branch=master)](https://travis-ci.org/dogtagpki/pki-nightly-test)

(C) 2008 Red Hat, Inc.
All rights reserved.

This Certificate System is open-source software.

Please comply with the LICENSE contained in each of
the individual components, and the EXPORT CONTROL
regulations defined at:

http://www.dogtagpki.org/wiki/PKI_Download

These directories contain the following:

* CMakeLists.txt
* LICENSE
* cmake

  These files and this directory contain
  the top-level files necessary to integrate
  the CMake build system in pki.

* README.md

  This file.

* base

  Contains most of the base source code
  needed to build this project.  Note that
  this directory does NOT contain
  implementation specific user-interface
  components required to build a working
  Certificate System.

* themes

  Contains the scripts and user-interface
  components to customize PKI web UI and
  console.

* scripts

  Contains "scripts" used by this
  certificate system.  This directory
  contains numerous "compose" scripts
  useful for building RPMS/SRPMS of the
  various certificate system components.

* specs

  Contains RPM spec files used for
  building RPMS/SRPMS of the various
  certificate system components.

* tools

  Contains utilities useful to
  certificate system components.

Detailed instructions for building, installing, and
running this project are located at:

http://www.dogtagpki.org/wiki/PKI_Main_Page


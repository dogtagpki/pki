// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifndef SELFTEST_H
#define SELFTEST_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include <stdio.h>

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#include "main/ConfigStore.h"


class SelfTest
{
  public:
    SelfTest();  
    ~SelfTest();
    static void Initialize (ConfigStore *cfg);
    static int runStartUpSelfTests (const char *nickname); /* per cert */
    static int runStartUpSelfTests (); /* general */
    static int runOnDemandSelfTests ();
    static int isOnDemandEnabled ();
    static int isOnDemandCritical ();

    static const int  nTests;
    static const char *TEST_NAMES[];

  protected:
    static const char *CFG_SELFTEST_STARTUP;
    static const char *CFG_SELFTEST_ONDEMAND;

  private: 
    static int isInitialized;
    static int StartupSystemCertsVerificationRun;
};

#endif

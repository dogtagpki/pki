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

#ifndef TPSSYSTEMCERTSVERIFICATION_H
#define TPSSYSTEMCERTSVERIFICATION_H

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
// #include "main/Util.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#include "main/ConfigStore.h"
#include "selftests/SelfTest.h"

class TPSSystemCertsVerification : public SelfTest
{

  public:
    TPSSystemCertsVerification();  
    ~TPSSystemCertsVerification();
    static void Initialize (ConfigStore *cfg);
    static int  runSelfTest ();
    static bool isStartupEnabled ();
    static bool isOnDemandEnabled ();
    static bool isStartupCritical ();
    static bool isOnDemandCritical ();
    static const char *TEST_NAME;

  private: 
    static bool startupEnabled;
    static bool onDemandEnabled;
    static bool startupCritical;
    static bool onDemandCritical;
    static int  initialized;
    static const char *CRITICAL_TEST_NAME;
    static const char *UNINITIALIZED_NICKNAME;
    static const char *SUBSYSTEM_NICKNAME;
};

#endif

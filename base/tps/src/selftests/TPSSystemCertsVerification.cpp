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


#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"

#include "cert.h"
#include "certt.h"

#ifdef __cplusplus
}   
#endif

#include "engine/RA.h"
#include "main/ConfigStore.h"
#include "selftests/TPSSystemCertsVerification.h"


int  TPSSystemCertsVerification::initialized = 0;
bool TPSSystemCertsVerification::startupEnabled = false;
bool TPSSystemCertsVerification::onDemandEnabled = false;
bool TPSSystemCertsVerification::startupCritical = false;
bool TPSSystemCertsVerification::onDemandCritical = false;
const char *TPSSystemCertsVerification::CRITICAL_TEST_NAME = "TPSSystemCertsVerification:critical";
const char *TPSSystemCertsVerification::TEST_NAME = "TPSSystemCertsVerification";
// for testing if system is initialized
const char *TPSSystemCertsVerification::UNINITIALIZED_NICKNAME = "[HSM_LABEL][NICKNAME]";
const char *TPSSystemCertsVerification::SUBSYSTEM_NICKNAME= "tps.cert.subsystem.nickname";


//default constructor
TPSSystemCertsVerification::TPSSystemCertsVerification()
{
}

TPSSystemCertsVerification::~TPSSystemCertsVerification()
{
}

void TPSSystemCertsVerification::Initialize (ConfigStore *cfg)
{
    if (TPSSystemCertsVerification::initialized == 0) {
        TPSSystemCertsVerification::initialized = 1;
        const char* s = cfg->GetConfigAsString(CFG_SELFTEST_STARTUP);
        if (s != NULL) {
            if (PL_strstr (s, TPSSystemCertsVerification::CRITICAL_TEST_NAME) != NULL) {
                startupCritical = true;
                startupEnabled = true;
            } else if (PL_strstr (s, TPSSystemCertsVerification::TEST_NAME) != NULL) {
                startupEnabled = true;
            }
        }
        const char* d = cfg->GetConfigAsString(CFG_SELFTEST_ONDEMAND);
        if (d != NULL) {
            if (PL_strstr (d, TPSSystemCertsVerification::CRITICAL_TEST_NAME) != NULL) {
                onDemandCritical = true;
                onDemandEnabled = true;
            } else if (PL_strstr (d, TPSSystemCertsVerification::TEST_NAME) != NULL) {
                onDemandEnabled = true;
            }
        }
        char* n = (char*)(cfg->GetConfigAsString(TPSSystemCertsVerification::SUBSYSTEM_NICKNAME));
        if (n != NULL && PL_strlen(n) > 0) {
            if (PL_strstr (n, TPSSystemCertsVerification::UNINITIALIZED_NICKNAME) != NULL) {
                TPSSystemCertsVerification::initialized = 0;
            }
        }
        if (TPSSystemCertsVerification::initialized == 1) {
            TPSSystemCertsVerification::initialized = 2;
        }
    }
    RA::SelfTestLog("TPSSystemCertsVerification::Initialize", "%s", ((initialized==2)?"successfully completed":"failed"));
}

// Error codes:
//   -1 -  failed system certs verification
// critical errors are negative

int TPSSystemCertsVerification::runSelfTest ()
{
    int rc = 0;

    if (TPSSystemCertsVerification::initialized == 2) {
        rc = RA::verifySystemCerts();
        if (rc == true) {
            return 0;
        } else {
            rc = -1;
        }
    }

    return rc;
}

bool TPSSystemCertsVerification::isStartupEnabled ()
{
    return startupEnabled;
}

bool TPSSystemCertsVerification::isOnDemandEnabled ()
{
    return onDemandEnabled;
}

bool TPSSystemCertsVerification::isStartupCritical ()
{
    return startupCritical;
}

bool TPSSystemCertsVerification::isOnDemandCritical ()
{
    return onDemandCritical;
}


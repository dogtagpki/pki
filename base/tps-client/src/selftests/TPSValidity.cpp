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
#include "selftests/TPSValidity.h"


int  TPSValidity::initialized = 0;
bool TPSValidity::startupEnabled = false;
bool TPSValidity::onDemandEnabled = false;
bool TPSValidity::startupCritical = false;
bool TPSValidity::onDemandCritical = false;
char *TPSValidity::nickname = 0;
const char *TPSValidity::UNINITIALIZED_NICKNAME = "[HSM_LABEL][NICKNAME]";
const char *TPSValidity::NICKNAME_NAME = "selftests.plugin.TPSValidity.nickname";
const char *TPSValidity::CRITICAL_TEST_NAME = "TPSValidity:critical";
const char *TPSValidity::TEST_NAME = "TPSValidity";


//default constructor
TPSValidity::TPSValidity()
{
}

TPSValidity::~TPSValidity()
{
}

void TPSValidity::Initialize (ConfigStore *cfg)
{
    if (TPSValidity::initialized == 0) {
        TPSValidity::initialized = 1;
        const char* s = cfg->GetConfigAsString(CFG_SELFTEST_STARTUP);
        if (s != NULL) {
            if (PL_strstr (s, TPSValidity::CRITICAL_TEST_NAME) != NULL) {
                startupCritical = true;
                startupEnabled = true;
            } else if (PL_strstr (s, TPSValidity::TEST_NAME) != NULL) {
                startupEnabled = true;
            }
        }
        const char* d = cfg->GetConfigAsString(CFG_SELFTEST_ONDEMAND);
        if (d != NULL) {
            if (PL_strstr (d, TPSValidity::CRITICAL_TEST_NAME) != NULL) {
                onDemandCritical = true;
                onDemandEnabled = true;
            } else if (PL_strstr (d, TPSValidity::TEST_NAME) != NULL) {
                onDemandEnabled = true;
            }
        }
        char* n = (char*)(cfg->GetConfigAsString(TPSValidity::NICKNAME_NAME));
        if (n != NULL && PL_strlen(n) > 0) {
            if (PL_strstr (n, TPSValidity::UNINITIALIZED_NICKNAME) != NULL) {
                TPSValidity::initialized = 0;
            } else {
                TPSValidity::nickname = n;
            }
        }
        if (TPSValidity::initialized == 1) {
            TPSValidity::initialized = 2;
        }
    }
    RA::SelfTestLog("TPSValidity::Initialize", "%s", ((initialized==2)?"successfully completed":"failed"));
}

// Error codes:
//   -1 - missing cert db handle
//    2 - missing cert
//   -3 - missing cert nickname
//    4 - secCertTimeExpired
//    5 - secCertTimeNotValidYet
// critical errors are negative

int TPSValidity::runSelfTest ()
{
    int rc = 0;

    if (TPSValidity::initialized == 2) {
        if (TPSValidity::nickname != NULL && PL_strlen(TPSValidity::nickname) > 0) {
            rc = TPSValidity::runSelfTest (TPSValidity::nickname);
        } else {
            rc = -3;
        }
    }

    return rc;
}

int TPSValidity::runSelfTest (const char *nick_name)
{
    SECCertTimeValidity certTimeValidity;
    PRTime now;
    int rc = 0;
    CERTCertDBHandle *handle = 0;
    CERTCertificate *cert = 0;

    if (TPSValidity::initialized == 2) {
        handle = CERT_GetDefaultCertDB();
        if (handle != 0) {
            cert = CERT_FindCertByNickname( handle, (char *) nick_name);
            if (cert != 0) {
                now = PR_Now();
                certTimeValidity = CERT_CheckCertValidTimes (cert, now, PR_FALSE);
                if (certTimeValidity == secCertTimeExpired) {
                    rc = 4;
                } else if (certTimeValidity == secCertTimeNotValidYet) {
                    rc = 5;
                }
                CERT_DestroyCertificate (cert);
                cert = 0;
            } else {
                rc = 2;
            }
        } else {
            rc = -1;
        }
    }

    return rc;
}

int TPSValidity::runSelfTest (const char *nick_name, CERTCertificate *cert)
{
    SECCertTimeValidity certTimeValidity;
    PRTime now;
    int rc = 0;

    if (TPSValidity::initialized == 2) {
        if (cert != 0) {
            now = PR_Now();
            certTimeValidity = CERT_CheckCertValidTimes (cert, now, PR_FALSE);
                if (certTimeValidity == secCertTimeExpired) {
                    rc = 4;
                } else if (certTimeValidity == secCertTimeNotValidYet) {
                    rc = 5;
                }
                CERT_DestroyCertificate (cert);
                cert = 0;
        } else if (nick_name != 0 && PL_strlen(nick_name) > 0) {
            rc = TPSValidity::runSelfTest (nick_name);
        } else {
            rc = TPSValidity::runSelfTest ();
        }
    }

    return rc;

}

bool TPSValidity::isStartupEnabled ()
{
    return startupEnabled;
}

bool TPSValidity::isOnDemandEnabled ()
{
    return onDemandEnabled;
}

bool TPSValidity::isStartupCritical ()
{
    return startupCritical;
}

bool TPSValidity::isOnDemandCritical ()
{
    return onDemandCritical;
}


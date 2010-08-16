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
#include "selftests/TPSPresence.h"


int  TPSPresence::initialized = 0;
bool TPSPresence::startupEnabled = false;
bool TPSPresence::onDemandEnabled = false;
bool TPSPresence::startupCritical = false;
bool TPSPresence::onDemandCritical = false;
char *TPSPresence::nickname = 0;
const char *TPSPresence::NICKNAME_NAME = "selftests.plugin.TPSPresence.nickname";
const char *TPSPresence::CRITICAL_TEST_NAME = "TPSPresence:critical";
const char *TPSPresence::TEST_NAME = "TPSPresence";

//default constructor
TPSPresence::TPSPresence()
{
}

TPSPresence::~TPSPresence()
{
}

void TPSPresence::Initialize (ConfigStore *cfg)
{
    if (TPSPresence::initialized == 0) {
        TPSPresence::initialized = 1;
        const char* s = cfg->GetConfigAsString(CFG_SELFTEST_STARTUP);
        if (s != 0) {
            if (PL_strstr (s, TPSPresence::CRITICAL_TEST_NAME) != 0) {
                startupCritical = true;
                startupEnabled = true;
            } else if (PL_strstr (s, TPSPresence::TEST_NAME) != 0) {
                startupEnabled = true;
            }
        }
        const char* d = cfg->GetConfigAsString(CFG_SELFTEST_ONDEMAND);
        if (d != 0) {
            if (PL_strstr (d, TPSPresence::CRITICAL_TEST_NAME) != 0) {
                onDemandCritical = true;
                onDemandEnabled = true;
            } else if (PL_strstr (d, TPSPresence::TEST_NAME) != 0) {
                onDemandEnabled = true;
            }
        }
        char* n = (char*)(cfg->GetConfigAsString(TPSPresence::NICKNAME_NAME));
        if (n != 0 && PL_strlen(n) > 0) {
            TPSPresence::nickname = n;
        }
        TPSPresence::initialized = 2;
    }
    RA::SelfTestLog("TPSPresence::Initialize", "%s", ((initialized==2)?"successfully completed":"failed"));
}

// Error codes:
//   -1 - missing cert db handle
//    2 - missing cert
//   -3 - missing cert nickname
//    4 - secCertTimeExpired
//    5 - secCertTimeNotValidYet
// critical errors are negative

int TPSPresence::runSelfTest ()
{
    int rc = 0;
    if (TPSPresence::nickname != 0 && PL_strlen(TPSPresence::nickname) > 0) {
        rc = TPSPresence::runSelfTest (TPSPresence::nickname);
    } else {
        rc = -3;
    }
    return rc;
}

int TPSPresence::runSelfTest (const char *nick_name)
{
    int rc = 0;
    CERTCertDBHandle *handle = 0;
    CERTCertificate *cert = 0;

    if (nick_name != 0 && PL_strlen(nick_name) > 0) {
        handle = CERT_GetDefaultCertDB();
        if (handle != 0) {
            cert = CERT_FindCertByNickname( handle, (char *) nick_name);
            if (cert != 0) {
                CERT_DestroyCertificate (cert);
                cert = 0;
            } else {
                rc = 2;
            }
        } else {
            rc = -1;
        }
    } else {
        rc = TPSPresence::runSelfTest ();
    }

    return rc;
}

int TPSPresence::runSelfTest (const char *nick_name, CERTCertificate **cert)
{
    int rc = 0;
    CERTCertDBHandle *handle = 0;

    handle = CERT_GetDefaultCertDB();
    if (handle != 0) {
        *cert = CERT_FindCertByNickname( handle, (char *) nick_name);
        if (*cert == NULL) {
            rc = 2;
        }
    } else {
        rc = 1;
    }

    return rc;
}

bool TPSPresence::isStartupEnabled ()
{
    return startupEnabled;
}

bool TPSPresence::isOnDemandEnabled ()
{
    return onDemandEnabled;
}

bool TPSPresence::isStartupCritical ()
{
    return startupCritical;
}

bool TPSPresence::isOnDemandCritical ()
{
    return onDemandCritical;
}



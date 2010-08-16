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
#include "selftests/SelfTest.h"
#include "selftests/TPSPresence.h"
#include "selftests/TPSValidity.h"


const char *SelfTest::CFG_SELFTEST_STARTUP = "selftests.container.order.startup";
const char *SelfTest::CFG_SELFTEST_ONDEMAND = "selftests.container.order.onDemand";
const int  SelfTest::nTests = 2;
const char *SelfTest::TEST_NAMES[SelfTest::nTests] = { TPSPresence::TEST_NAME, TPSValidity::TEST_NAME };

int SelfTest::isInitialized = 0;

SelfTest::SelfTest()
{
}

SelfTest::~SelfTest()
{
}

void SelfTest::Initialize (ConfigStore *cfg)
{
    if (SelfTest::isInitialized == 0) {
        SelfTest::isInitialized = 1;
        TPSPresence::Initialize (cfg);
        TPSValidity::Initialize (cfg);
        SelfTest::isInitialized = 2;
    }
    RA::SelfTestLog("SelfTest::Initialize", "%s", ((isInitialized==2)?"successfully completed":"failed"));
}

// Error codes:
//   -1 - missing cert db handle
//    2 - missing cert
//   -3 - missing cert nickname
//    4 - secCertTimeExpired
//    5 - secCertTimeNotValidYet
// critical errors are negative

int SelfTest::runStartUpSelfTests (const char *nickname)
{
    int rc = 0;
    CERTCertificate *cert = 0;

    RA::SelfTestLog("SelfTest::runStartUpSelfTests", "starting");
    if (TPSPresence::isStartupEnabled()) {
        rc = TPSPresence::runSelfTest(nickname, &cert);
    }
    if (rc != 0 && TPSPresence::isStartupCritical()) {
        if (rc > 0) rc *= -1;
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "Critical TPSPresence self test failure: %d", rc);
        return rc;
    } else if (rc != 0) {
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "Noncritical TPSPresence self test failure: %d", rc);
    } else {
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "TPSPresence self test has been successfully completed.");
    }
    if (TPSValidity::isStartupEnabled()) {
        rc = TPSValidity::runSelfTest(nickname, cert);
    }
    if (cert != 0) {
        CERT_DestroyCertificate (cert);
        cert = 0;
    }
    if (rc != 0 && TPSValidity::isStartupCritical()) {
        if (rc > 0) rc *= -1;
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "Critical TPSValidity self test failure: %d", rc);
        return rc;
    } else if (rc != 0) {
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "Noncritical TPSValidity self test failure: %d", rc);
    } else {
        RA::SelfTestLog("SelfTest::runStartUpSelfTests", "TPSValidity self test has been successfully completed.");
    }
    RA::SelfTestLog("SelfTest::runStartUpSelfTests", "done");
    return 0;
}

int SelfTest::runOnDemandSelfTests ()
{
    int rc = 0;
    RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "starting");
    if (TPSPresence::isOnDemandEnabled()) {
        rc = TPSPresence::runSelfTest();
    }
    if (rc != 0 && TPSPresence::isOnDemandCritical()) {
        if (rc > 0) rc *= -1;
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "Critical TPSPresence self test failure: %d", rc);
        return rc;
    } else if (rc != 0) {
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "Noncritical TPSPresence self test failure: %d", rc);
    } else {
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "TPSPresence self test has been successfully completed.");
    }
    if (TPSValidity::isOnDemandEnabled()) {
        rc = TPSValidity::runSelfTest();
    }
    if (rc != 0 && TPSValidity::isOnDemandCritical()) {
        if (rc > 0) rc *= -1;
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "Critical TPSValidity self test failure: %d", rc);
        return rc;
    } else if (rc != 0) {
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "Noncritical TPSValidity self test failure: %d", rc);
    } else {
        RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "TPSValidity self test has been successfully completed.");
    }
    RA::SelfTestLog("SelfTest::runOnDemandSelfTests", "done");
    return rc;
}

int SelfTest::isOnDemandEnabled ()
{
    int n = 0;
    if (TPSPresence::isOnDemandEnabled()) n++;
    if (TPSValidity::isOnDemandEnabled()) n += 2;
    return n;
}

int SelfTest::isOnDemandCritical ()
{
    int n = 0;
    if (TPSPresence::isOnDemandCritical()) n++;
    if (TPSValidity::isOnDemandCritical()) n += 2;
    return n;
}


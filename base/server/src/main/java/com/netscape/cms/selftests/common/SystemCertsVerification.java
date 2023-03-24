// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
// package statement //
///////////////////////

package com.netscape.cms.selftests.common;

///////////////////////
// import statements //
///////////////////////

import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.LogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.cms.selftests.SelfTest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a self test to check the system certs
 * of the subsystem
 * <P>
 *
 * @version $Revision: $, $Date: $
 */
public class SystemCertsVerification
        extends SelfTest {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////////
    // SystemCertsVerification parameters //
    ///////////////////////////

    // parameter information
    public static final String PROP_SUB_ID = "SubId";
    public static final String PROP_FULL_CA_OCSP_VERIFY = "FullCAandOCSPVerify";
    private String mSubId = null;
    private boolean mFullCAandOCSPVerify = false;

    /////////////////////
    // default methods //
    /////////////////////

    ////////////////////////
    // SystemCertsVerification methods //
    ////////////////////////

    /**
     * Initializes this subsystem with the configuration store
     * associated with this instance name.
     * <P>
     *
     * @param subsystem the associated subsystem
     * @param instanceName the name of this self test instance
     * @param parameters configuration store (self test parameters)
     * @exception EDuplicateSelfTestException subsystem has duplicate name/value
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    @Override
    public void initSelfTest(SelfTestSubsystem subsystem,
                              String instanceName,
                              ConfigStore parameters)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        super.initSelfTest(subsystem, instanceName, parameters);

        // retrieve mandatory parameter(s)
        try {
            mSubId = mConfig.getString(PROP_SUB_ID);
            if (mSubId != null) {
                mSubId = mSubId.trim();
            } else {
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                        CMS.getLogMessage(
                                                "SELFTESTS_MISSING_VALUES",
                                                getSelfTestName(),
                                                mPrefix
                                                        + "."
                                                        + PROP_SUB_ID));

                throw new EMissingSelfTestException(PROP_SUB_ID);
            }
        } catch (EBaseException e) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage(
                                            "SELFTESTS_MISSING_NAME",
                                            getSelfTestName(),
                                            mPrefix
                                                    + "."
                                                    + PROP_SUB_ID));

            throw new EMissingSelfTestException(mPrefix,
                                                 PROP_SUB_ID,
                                                 null);
        }

        // retrieve optional parameter(s)

        try {
            mFullCAandOCSPVerify = mConfig.getBoolean(PROP_FULL_CA_OCSP_VERIFY, false);
        } catch (EBaseException e) {
            //Since this is fully optional, keep going.
            mFullCAandOCSPVerify = false;
        }

        return;
    }

    /**
     * Notifies this subsystem if it is in execution mode.
     * <P>
     *
     * @exception ESelfTestException failed to start
     */
    @Override
    public void startupSelfTest()
            throws ESelfTestException {
        return;
    }

    /**
     * Stops this subsystem. The subsystem may call shutdownSelfTest
     * anytime after initialization.
     * <P>
     */
    @Override
    public void shutdownSelfTest() {
        return;
    }

    /**
     * Returns the name associated with this self test. This method may
     * return null if the self test has not been intialized.
     * <P>
     *
     * @return instanceName of this self test
     */
    @Override
    public String getSelfTestName() {
        return super.getSelfTestName();
    }

    /**
     * Returns the root configuration storage (self test parameters)
     * associated with this subsystem.
     * <P>
     *
     * @return configuration store (self test parameters) of this subsystem
     */
    @Override
    public ConfigStore getSelfTestConfigStore() {
        return super.getSelfTestConfigStore();
    }

    /**
     * Retrieves description associated with an individual self test.
     * This method may return null.
     * <P>
     *
     * @param locale locale of the client that requests the description
     * @return description of self test
     */
    @Override
    public String getSelfTestDescription(Locale locale) {
        return CMS.getUserMessage(locale,
                                   "CMS_SELFTESTS_SYSTEM_CERTS_VERIFICATION_DESCRIPTION");
    }

    /**
     * Execute an individual self test.
     * <P>
     *
     * @param logger specifies logging subsystem
     * @exception Exception self test exception
     */
    @Override
    public void runSelfTest(LogEventListener logger) throws Exception {

        try {
            if (("ca".equalsIgnoreCase(mSubId) || "ocsp".equalsIgnoreCase(mSubId)) && !mFullCAandOCSPVerify) {
                //Perform validity only
                engine.verifySystemCerts(true);
            } else {
                engine.verifySystemCerts(false);
            }

            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_COMMON_SYSTEM_CERTS_VERIFICATION_SUCCESS",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);

        } catch (Exception e) {
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_COMMON_SYSTEM_CERTS_VERIFICATION_FAILURE",
                    getSelfTestName(), e.getMessage());
            mSelfTestSubsystem.log(logger, logMessage);
            throw e;
        }
    }
}

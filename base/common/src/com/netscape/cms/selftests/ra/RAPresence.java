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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
// package statement //
///////////////////////

package com.netscape.cms.selftests.ra;

///////////////////////
// import statements //
///////////////////////

import java.security.PublicKey;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.cms.selftests.ASelfTest;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a self test to check for RA presence.
 * <P>
 *
 * <PRE>
 * NOTE:  This self-test is for Registration Authorities prior to
 *        Netscape Certificate Management System 7.0.  It does NOT
 *        apply to the Registration Authority found in
 *        Red Hat Certificate System 7.3 or later (including
 *        ALL versions of Dogtag Certificate System).
 * </PRE>
 * <P>
 *
 * @deprecated
 * @author mharmsen
 * @author thomask
 * @version $Revision$, $Date$
 */
public class RAPresence
        extends ASelfTest {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////////
    // RAPresence parameters //
    ///////////////////////////

    // parameter information
    public static final String PROP_RA_SUB_ID = "RaSubId";
    private String mRaSubId = null;

    /////////////////////
    // default methods //
    /////////////////////

    ////////////////////////
    // RAPresence methods //
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
    public void initSelfTest(ISelfTestSubsystem subsystem,
                              String instanceName,
                              IConfigStore parameters)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        super.initSelfTest(subsystem, instanceName, parameters);

        // retrieve mandatory parameter(s)
        try {
            mRaSubId = mConfig.getString(PROP_RA_SUB_ID);
            if (mRaSubId != null) {
                mRaSubId = mRaSubId.trim();
            } else {
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                        CMS.getLogMessage(
                                                "SELFTESTS_MISSING_VALUES",
                                                getSelfTestName(),
                                                mPrefix
                                                        + "."
                                                        + PROP_RA_SUB_ID));

                throw new EMissingSelfTestException(PROP_RA_SUB_ID);
            }
        } catch (EBaseException e) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage(
                                            "SELFTESTS_MISSING_NAME",
                                            getSelfTestName(),
                                            mPrefix
                                                    + "."
                                                    + PROP_RA_SUB_ID));

            throw new EMissingSelfTestException(mPrefix,
                                                 PROP_RA_SUB_ID,
                                                 null);
        }

        // retrieve optional parameter(s)

        return;
    }

    /**
     * Notifies this subsystem if it is in execution mode.
     * <P>
     *
     * @exception ESelfTestException failed to start
     */
    public void startupSelfTest()
            throws ESelfTestException {
        return;
    }

    /**
     * Stops this subsystem. The subsystem may call shutdownSelfTest
     * anytime after initialization.
     * <P>
     */
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
    public IConfigStore getSelfTestConfigStore() {
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
    public String getSelfTestDescription(Locale locale) {
        return CMS.getUserMessage(locale,
                                   "CMS_SELFTESTS_RA_PRESENCE_DESCRIPTION");
    }

    /**
     * Execute an individual self test.
     * <P>
     *
     * @param logger specifies logging subsystem
     * @exception ESelfTestException self test exception
     */
    public void runSelfTest(ILogEventListener logger)
            throws ESelfTestException {
        String logMessage = null;
        IRegistrationAuthority ra = null;
        org.mozilla.jss.crypto.X509Certificate raCert = null;
        PublicKey raPubKey = null;

        ra = (IRegistrationAuthority) CMS.getSubsystem(mRaSubId);

        if (ra == null) {
            // log that the RA is not installed
            logMessage = CMS.getLogMessage("SELFTESTS_RA_IS_NOT_PRESENT",
                                            getSelfTestName());

            mSelfTestSubsystem.log(logger,
                                    logMessage);

            throw new ESelfTestException(logMessage);
        } else {
            // Retrieve the RA certificate
            raCert = ra.getRACert();

            if (raCert == null) {
                // log that the RA is not yet initialized
                logMessage = CMS.getLogMessage(
                             "SELFTESTS_RA_IS_NOT_INITIALIZED",
                             getSelfTestName());

                mSelfTestSubsystem.log(logger,
                                        logMessage);

                throw new ESelfTestException(logMessage);
            }

            // Retrieve the RA certificate public key
            raPubKey = raCert.getPublicKey();

            if (raPubKey == null) {
                // log that something is seriously wrong with the RA
                logMessage = CMS.getLogMessage("SELFTESTS_RA_IS_CORRUPT",
                                                getSelfTestName());

                mSelfTestSubsystem.log(logger,
                                        logMessage);

                throw new ESelfTestException(logMessage);
            }

            // log that the RA is present
            logMessage = CMS.getLogMessage("SELFTESTS_RA_IS_PRESENT",
                                            getSelfTestName());

            mSelfTestSubsystem.log(logger,
                                    logMessage);
        }

        return;
    }
}

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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.selftests;

import java.security.PublicKey;
import java.util.Locale;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;

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

/**
 * This class implements a self test to check for TPS presence.
 * <P>
 *
 * @author alee
 * @version $Revision$, $Date$
 */
public class TPSPresence extends SelfTest {

    public static final String PROP_TPS_SUB_ID = "TpsSubId";
    private String tpsSubId = null;

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
    public void initSelfTest(
            SelfTestSubsystem subsystem,
            String instanceName,
            ConfigStore parameters) throws EDuplicateSelfTestException, EInvalidSelfTestException,
            EMissingSelfTestException {
        super.initSelfTest(subsystem, instanceName, parameters);

        try {
            tpsSubId = mConfig.getString(PROP_TPS_SUB_ID);
            if (tpsSubId != null) {
                tpsSubId = tpsSubId.trim();
            } else {
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                        CMS.getLogMessage("SELFTESTS_MISSING_VALUES", getSelfTestName(),
                                mPrefix + "." + PROP_TPS_SUB_ID));

                throw new EMissingSelfTestException(PROP_TPS_SUB_ID);
            }
        } catch (EBaseException e) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                    CMS.getLogMessage("SELFTESTS_MISSING_NAME", getSelfTestName(),
                            mPrefix + "." + PROP_TPS_SUB_ID));

            throw new EMissingSelfTestException(mPrefix, PROP_TPS_SUB_ID, null);
        }
    }

    /**
     * Notifies this subsystem if it is in execution mode.
     * <P>
     *
     * @exception ESelfTestException failed to start
     */
    @Override
    public void startupSelfTest() throws ESelfTestException {
    }

    /**
     * Stops this subsystem. The subsystem may call shutdownSelfTest
     * anytime after initialization.
     * <P>
     */
    @Override
    public void shutdownSelfTest() {
    }

    /**
     * Returns the name associated with this self test. This method may
     * return null if the self test has not been initialized.
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
                "CMS_SELFTESTS_TPS_PRESENCE_DESCRIPTION");
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

        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem tps = (TPSSubsystem) engine.getSubsystem(tpsSubId);
        if (tps == null) {
            // log that the TPS is not installed
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_PRESENT",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // Retrieve the TPS certificate
        org.mozilla.jss.crypto.X509Certificate tpsCert;
        try {
            tpsCert = tps.getSubsystemCert();

        } catch (Exception e) {
            // cert does not exist or is not yet configured
            // tpsCert will remain null
            // log that the TPS is not yet initialized
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_INITIALIZED",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw e;
        }

        if (tpsCert == null) {
            // log that the TPS is not yet initialized
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_INITIALIZED",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // Retrieve the TPS certificate public key
        PublicKey tpsPubKey = tpsCert.getPublicKey();
        if (tpsPubKey == null) {
            // log that something is seriously wrong with the TPS
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_CORRUPT",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // log that the TPS is present
        String logMessage = CMS.getLogMessage(
                "SELFTESTS_TPS_IS_PRESENT",
                getSelfTestName());
        mSelfTestSubsystem.log(logger, logMessage);
    }
}

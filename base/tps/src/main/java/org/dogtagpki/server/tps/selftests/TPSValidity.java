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

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Locale;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.cms.selftests.ASelfTest;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements a self test to check the validity of the TPS.
 * <P>
 *
 * @author alee
 * @version $Revision$, $Date$
 */
public class TPSValidity extends ASelfTest {

    // parameter information
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
    public void initSelfTest(ISelfTestSubsystem subsystem, String instanceName,
            IConfigStore parameters) throws EDuplicateSelfTestException,
            EInvalidSelfTestException, EMissingSelfTestException {
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
    @Override
    public String getSelfTestDescription(Locale locale) {
        return CMS.getUserMessage(locale,
                "CMS_SELFTESTS_TPS_VALIDITY_DESCRIPTION");
    }

    /**
     * Execute an individual self test.
     * <P>
     *
     * @param logger specifies logging subsystem
     * @exception Exception self test exception
     */
    @Override
    public void runSelfTest(ILogEventListener logger) throws Exception {

        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        TPSSubsystem tps = (TPSSubsystem) engine.getSubsystem(tpsSubId);
        if (tps == null) {
            // log that the TPS is not installed
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_PRESENT",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // Retrieve the TPS subsystem certificate
        X509CertImpl tpsCert;
        try {
            tpsCert = new X509CertImpl(tps.getSubsystemCert().getEncoded());
        } catch (Exception e) {
            // certificate is not present or has not been configured
            // log that the TPS is not yet initialized
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_INITIALIZED",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw e;
        }

        // Check the TPS validity period
        try {
            tpsCert.checkValidity();

        } catch (CertificateNotYetValidException e) {
            // log that the TPS is not yet valid
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_NOT_YET_VALID",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw e;

        } catch (CertificateExpiredException e) {
            // log that the TPS is expired
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_TPS_IS_EXPIRED",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw e;
        }

        // log that the TPS is valid
        String logMessage = CMS.getLogMessage(
                "SELFTESTS_TPS_IS_VALID",
                getSelfTestName());
        mSelfTestSubsystem.log(logger, logMessage);
    }
}

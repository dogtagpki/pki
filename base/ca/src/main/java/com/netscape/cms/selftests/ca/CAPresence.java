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

package com.netscape.cms.selftests.ca;

///////////////////////
// import statements //
///////////////////////

import java.security.cert.CertificateParsingException;
import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

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

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a self test to check for CA presence.
 * <P>
 *
 * @author mharmsen
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CAPresence
        extends ASelfTest {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////////
    // CAPresence parameters //
    ///////////////////////////

    // parameter information
    public static final String PROP_CA_SUB_ID = "CaSubId";
    private String mCaSubId = null;

    /////////////////////
    // default methods //
    /////////////////////

    ////////////////////////
    // CAPresence methods //
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
    public void initSelfTest(ISelfTestSubsystem subsystem,
                              String instanceName,
                              IConfigStore parameters)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        super.initSelfTest(subsystem, instanceName, parameters);

        // retrieve mandatory parameter(s)
        try {
            mCaSubId = mConfig.getString(PROP_CA_SUB_ID);
            if (mCaSubId != null) {
                mCaSubId = mCaSubId.trim();
            } else {
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                        CMS.getLogMessage(
                                                "SELFTESTS_MISSING_VALUES",
                                                getSelfTestName(),
                                                mPrefix
                                                        + "."
                                                        + PROP_CA_SUB_ID));

                throw new EMissingSelfTestException(PROP_CA_SUB_ID);
            }
        } catch (EBaseException e) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage(
                                            "SELFTESTS_MISSING_NAME",
                                            getSelfTestName(),
                                            mPrefix
                                                    + "."
                                                    + PROP_CA_SUB_ID));

            throw new EMissingSelfTestException(mPrefix,
                                                 PROP_CA_SUB_ID,
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
                                   "CMS_SELFTESTS_CA_PRESENCE_DESCRIPTION");
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

        CAEngine engine = CAEngine.getInstance();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(mCaSubId);
        if (ca == null) {
            // log that the CA is not installed
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_CA_IS_NOT_PRESENT",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // Retrieve the CA certificate
        X509CertImpl caCert = ca.getCACert();
        if (caCert == null) {
            // log that the CA is not yet initialized
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_CA_IS_NOT_INITIALIZED",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // Retrieve the CA certificate public key
        X509Key caPubKey;
        try {
            caPubKey = (X509Key) caCert.get(X509CertImpl.PUBLIC_KEY);

        } catch (CertificateParsingException e) {
            // log that something is seriously wrong with the CA
            mSelfTestSubsystem.log(logger, e.toString());
            throw e;
        }

        if (caPubKey == null) {
            // log that something is seriously wrong with the CA
            String logMessage = CMS.getLogMessage(
                    "SELFTESTS_CA_IS_CORRUPT",
                    getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new Exception(logMessage);
        }

        // log that the CA is present
        String logMessage = CMS.getLogMessage(
                "SELFTESTS_CA_IS_PRESENT",
                getSelfTestName());
        mSelfTestSubsystem.log(logger, logMessage);
    }
}

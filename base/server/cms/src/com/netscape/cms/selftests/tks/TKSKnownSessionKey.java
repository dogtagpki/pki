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

package com.netscape.cms.selftests.tks;

///////////////////////
// import statements //
///////////////////////

import java.util.Arrays;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.cms.selftests.ASelfTest;
import com.netscape.symkey.SessionKey;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a self test to check for TKS known session key.
 * <P>
 *
 * @author mharmsen
 * @author thomask
 * @author awnuk
 * @version $Revision$, $Date$
 */
public class TKSKnownSessionKey
        extends ASelfTest {
    // parameter information
    public static final String PROP_TKS_SUB_ID = "TksSubId";
    private String mTksSubId = null;
    private String mToken = null;
    private String mUseSoftToken = null;
    private String mKeyName = null;
    private byte[] mKeyInfo = null;
    private byte[] mCardChallenge = null;
    private byte[] mHostChallenge = null;
    private byte[] mCUID = null;
    private byte[] mMacKey = null;
    private byte[] mSessionKey = null;

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
        ISubsystem tks = null;
        IConfigStore tksConfig = null;

        super.initSelfTest(subsystem, instanceName, parameters);

        mTksSubId = getConfigString(PROP_TKS_SUB_ID);
        mToken = getConfigString("token");
        mKeyName = getConfigString("keyName");
        mCardChallenge = getConfigByteArray("cardChallenge", 8);
        mHostChallenge = getConfigByteArray("hostChallenge", 8);
        mKeyInfo = getConfigByteArray("keyName", 2);
        mCUID = getConfigByteArray("CUID", 10);
        mMacKey = getConfigByteArray("macKey", 16);
        mUseSoftToken = getConfigString("useSoftToken");

        String defKeySetMacKey = null;
        tks = CMS.getSubsystem(mTksSubId);
        if (tks != null) {
            tksConfig = tks.getConfigStore();
            if (tksConfig != null) {
                try {
                    defKeySetMacKey = tksConfig.getString("defKeySet.mac_key");
                    byte defMacKey[] = com.netscape.cmsutil.util.Utils.SpecialDecode(defKeySetMacKey);
                    if (!Arrays.equals(mMacKey, defMacKey)) {
                        defKeySetMacKey = null;
                    }
                } catch (EBaseException e) {
                    defKeySetMacKey = null;
                }
            }
        }
        if (defKeySetMacKey == null) {
            CMS.debug("TKSKnownSessionKey: invalid mac key");
            CMS.debug("TKSKnownSessionKey self test FAILED");
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage("SELFTESTS_INVALID_VALUES",
                                            getSelfTestName(), mPrefix + "." + "macKey"));
            throw new EInvalidSelfTestException(mPrefix, "macKey", null);
        }

        try {
            mSessionKey = getConfigByteArray("sessionKey", 16);
        } catch (EMissingSelfTestException e) {
            if (mSessionKey == null) {
                mSessionKey = SessionKey.ComputeSessionKey(mToken, mKeyName,
                                                            mCardChallenge, mHostChallenge,
                                                            mKeyInfo, mCUID, mMacKey, mUseSoftToken, null, null);
                if (mSessionKey == null || mSessionKey.length != 16) {
                    mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                            CMS.getLogMessage("SELFTESTS_MISSING_VALUES",
                                                    getSelfTestName(), mPrefix + ".sessionKey"));
                    throw new EMissingSelfTestException("sessionKey");
                }
                String sessionKey = SpecialEncode(mSessionKey);
                mConfig.putString("sessionKey", sessionKey);
                try {
                    CMS.getConfigStore().commit(true);
                } catch (EBaseException be) {
                    mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                            CMS.getLogMessage("SELFTESTS_MISSING_VALUES",
                                                    getSelfTestName(), mPrefix + ".sessionKey"));
                    throw new EMissingSelfTestException("sessionKey");
                }
            }
        }

        return;
    }

    private String SpecialEncode(byte data[]) {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < data.length; i++) {
            sb.append("#");
            if ((data[i] & 0xff) < 16) {
                sb.append("0");
            }
            sb.append(Integer.toHexString((data[i] & 0xff)));
        }

        return sb.toString();
    }

    private String getConfigString(String name) throws EMissingSelfTestException {
        String value = null;

        try {
            value = mConfig.getString(name);
            if (value != null) {
                value = value.trim();
            } else {
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                        CMS.getLogMessage("SELFTESTS_MISSING_VALUES",
                                                getSelfTestName(), mPrefix + "." + name));
                throw new EMissingSelfTestException(name);
            }
        } catch (EBaseException e) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage("SELFTESTS_MISSING_NAME",
                                            getSelfTestName(), mPrefix + "." + name));
            throw new EMissingSelfTestException(mPrefix, name, null);
        }

        return value;
    }

    private byte[] getConfigByteArray(String name, int size) throws EMissingSelfTestException,
                                                                     EInvalidSelfTestException {
        String stringValue = getConfigString(name);

        byte byteValue[] = com.netscape.cmsutil.util.Utils.SpecialDecode(stringValue);
        if (byteValue == null) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage("SELFTESTS_MISSING_NAME",
                                            getSelfTestName(), mPrefix + "." + name));
            throw new EMissingSelfTestException(name);
        }
        if (byteValue.length != size) {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                                    CMS.getLogMessage("SELFTESTS_INVALID_VALUES",
                                            getSelfTestName(), mPrefix + "." + name));
            throw new EInvalidSelfTestException(mPrefix, name, stringValue);
        }

        return byteValue;
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
        return CMS.getUserMessage(locale, "CMS_SELFTESTS_TKS_PRESENCE_DESCRIPTION");
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
        IConfigStore cs = CMS.getConfigStore();
        String sharedSecretName;
        try {
            boolean useNewNames = cs.getBoolean("tks.useNewSharedSecretNames", false);
            if (useNewNames) {
                String tpsList = cs.getString("tps.list", "");
                if (tpsList.isEmpty()) {
                    CMS.debug("TKSKnownSessionKey: no shared secrets configured, exiting");
                    return;
                }

                for (String tpsID : tpsList.split(",")) {
                    sharedSecretName = cs.getString("tps." + tpsID + ".nickname", "");
                    if (!sharedSecretName.isEmpty()) {
                        CMS.debug("TKSKnownSessionKey: testing with key " + sharedSecretName);
                        generateSessionKey(logger, sharedSecretName);
                    }
                }
            } else {
                // legacy systems
                sharedSecretName = cs.getString("tks.tksSharedSymKeyName", "sharedSecret");
                generateSessionKey(logger, sharedSecretName);
            }
        } catch (EBaseException e) {
            e.printStackTrace();
            CMS.debug("TKSKnownSessionKey: failed to read config file to set up test");
            String logMessage = CMS.getLogMessage("SELFTESTS_TKS_FAILED", getSelfTestName(), getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new ESelfTestException(logMessage);
        }
        return;
    }

    private void generateSessionKey(ILogEventListener logger, String sharedSecretName) throws ESelfTestException {
        String logMessage;
        String keySet = "defKeySet";

        byte[] sessionKey = SessionKey.ComputeSessionKey(
                mToken, mKeyName, mCardChallenge, mHostChallenge, mKeyInfo,
                mCUID, mMacKey, mUseSoftToken, keySet, sharedSecretName);

        // Now we just see if we can successfully generate a session key.
        // For FIPS compliance, the routine now returns a wrapped key, which can't be extracted and compared.
        if (sessionKey == null) {
            CMS.debug("TKSKnownSessionKey: generated no session key");
            CMS.debug("TKSKnownSessionKey self test FAILED");
            logMessage = CMS.getLogMessage("SELFTESTS_TKS_FAILED", getSelfTestName(), getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            throw new ESelfTestException(logMessage);
        } else {
            logMessage = CMS.getLogMessage("SELFTESTS_TKS_SUCCEEDED", getSelfTestName(), getSelfTestName());
            mSelfTestSubsystem.log(logger, logMessage);
            CMS.debug("TKSKnownSessionKey self test SUCCEEDED");
        }
    }
}

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
package com.netscape.cmscore.authentication;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.util.Utils;

/**
 * Challenge phrase based authentication.
 * Maps a certificate to the request in the
 * internal database and further compares the challenge phrase with
 * that from the EE input.
 * <P>
 *
 * @author cfu chrisho
 * @version $Revision$, $Date$
 */
public class ChallengePhraseAuthentication implements IAuthManager {

    /* result auth token attributes */
    public static final String TOKEN_CERT_SERIAL = "certSerialToRevoke";

    /* required credentials */
    public static final String CRED_CERT_SERIAL = IAuthManager.CRED_CERT_SERIAL_TO_REVOKE;
    public static final String CRED_CHALLENGE = "challengePhrase";
    protected String[] mRequiredCreds = { CRED_CERT_SERIAL, CRED_CHALLENGE };

    /* config parameters to pass to console (none) */
    protected static String[] mConfigParams = null;
    protected ICertificateAuthority mCA = null;
    protected ICertificateRepository mCertDB = null;

    private String mName = null;
    private String mImplName = null;
    private IConfigStore mConfig = null;

    private ILogger mLogger = CMS.getLogger();
    private MessageDigest mSHADigest = null;

    // request attributes hacks
    public static final String CHALLENGE_PHRASE = CRED_CHALLENGE;
    public static final String SUBJECTNAME = "subjectName";
    public static final String SERIALNUMBER = "serialNumber";
    public static final String SERIALNOARRAY = "serialNoArray";

    public ChallengePhraseAuthentication() {
    }

    /**
     * initializes the ChallengePhraseAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing all available authentication managers.
     *
     * @param name The name of this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config The configuration store for this authentication manager.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        try {
            mSHADigest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.getMessage()));
        }

        log(ILogger.LL_INFO, CMS.getLogMessage("INIT_DONE", name));
    }

    /**
     * Gets the name of this authentication manager.
     */
    public String getName() {
        return mName;
    }

    /**
     * Gets the plugin name of authentication manager.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * authenticates revocation of a certification by a challenge phrase
     * <p>
     * called by other subsystems or their servlets to authenticate a revocation request
     *
     * @param authCred - authentication credential that contains
     *            a Certificate to revoke
     * @return the authentication token that contains the request id
     *
     * @exception EMissingCredential If a required credential for this
     *                authentication manager is missing.
     * @exception EInvalidCredentials If credentials cannot be authenticated.
     * @exception EBaseException If an internal error occurred.
     * @see com.netscape.certsrv.authentication.AuthToken
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {
        mCA = (ICertificateAuthority)
                SubsystemRegistry.getInstance().get("ca");

        if (mCA != null) {
            mCertDB = mCA.getCertificateRepository();
        }

        AuthToken authToken = new AuthToken(this);

        /*
         X509Certificate[] x509Certs =
         (X509Certificate[]) authCred.get(CRED_CERT);
         if (x509Certs == null) {
         log(ILogger.LL_FAILURE,
         " missing cert credential.");
         throw new EMissingCredential(CRED_CERT_SERIAL);
         }
         */

        String serialNumString = (String) authCred.get(CRED_CERT_SERIAL);

        BigInteger serialNum = null;

        if (serialNumString == null || serialNumString.equals(""))
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CERT_SERIAL));
        else {
            //serialNumString = getDecimalStr(serialNumString);
            try {
                serialNumString = serialNumString.trim();
                if (serialNumString.startsWith("0x") || serialNumString.startsWith("0X")) {
                    serialNum = new
                            BigInteger(serialNumString.substring(2), 16);
                } else {
                    serialNum = new
                            BigInteger(serialNumString);
                }

            } catch (NumberFormatException e) {
                throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                        "Invalid serial number."));
            }
        }

        String challenge = (String) authCred.get(CRED_CHALLENGE);

        if (challenge == null) {
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CHALLENGE));
        }
        if (challenge.equals("")) {
            // empty challenge not allowed
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_REVO_ATTEMPT", serialNum.toString()));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        /* maybe later
         if (mCertDB.isCertificateRevoked(cert) != null) {
         log(ILogger.LL_FAILURE,
         "Certificate has already been revoked.");
         // throw something else...cfu
         throw new EInvalidCredentials();
         }
         */

        BigInteger[] bigIntArray = null;

        // check challenge phrase against request
        /*
         * map cert to a request: a cert serial number maps to a
         * cert record in the internal db, from the cert record,
         * where we'll find the challenge phrase
         */
        if (mCertDB != null) { /* is CA */
            CertRecord record = null;

            try {
                record = (CertRecord) mCertDB.readCertificateRecord(serialNum);
            } catch (EBaseException ee) {
                if (Debug.ON) {
                    Debug.trace(ee.toString());
                }
            }
            if (record != null) {
                String status = record.getStatus();

                if (!status.equals("REVOKED")) {
                    boolean samepwd = compareChallengePassword(record, challenge);

                    if (samepwd) {
                        bigIntArray = new BigInteger[1];
                        bigIntArray[0] = record.getSerialNumber();
                    } else
                        throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                                "Invalid password."));

                } else {
                    bigIntArray = new BigInteger[0];
                }
            } else {
                bigIntArray = new BigInteger[0];
            }
        } else {

            /*
             * ra, build a request and send through the connection for
             * authentication
             */
            IRequestQueue queue = getReqQueue();

            if (queue != null) {
                IRequest checkChallengeReq = null;

                checkChallengeReq =
                        queue.newRequest(IRequest.REVOCATION_CHECK_CHALLENGE_REQUEST);
                checkChallengeReq.setExtData(CHALLENGE_PHRASE, challenge);
                // pass just serial number instead of whole cert
                if (serialNum != null)
                    checkChallengeReq.setExtData(SERIALNUMBER, serialNum);
                queue.processRequest(checkChallengeReq);
                // check request status...
                RequestStatus status = checkChallengeReq.getRequestStatus();

                if (status == RequestStatus.COMPLETE) {
                    bigIntArray = checkChallengeReq.getExtDataInBigIntegerArray("serialNoArray");
                } else {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_INCOMPLETE_REQUEST"));
                }
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_FAILED_GET_QUEUE"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_REVOCATION_CHALLENGE_QUEUE_FAILED"));
            }
        } // else, ra
        if (bigIntArray != null && bigIntArray.length > 0) {
            if (Debug.ON) {
                Debug.trace("challenge authentication serialno array not null");
                for (int i = 0; i < bigIntArray.length; i++)
                    Debug.trace("challenge auth serialno " + bigIntArray[i]);
            }
        }
        if (Debug.ON) {
            Debug.trace("challenge authentication set " + TOKEN_CERT_SERIAL);
        }
        authToken.set(TOKEN_CERT_SERIAL, bigIntArray);

        return authToken;
    }

    private boolean compareChallengePassword(CertRecord record, String pwd)
            throws EBaseException {
        MetaInfo metaInfo = (MetaInfo) record.get(CertRecord.ATTR_META_INFO);

        if (metaInfo == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "metaInfo"));
        }

        if (pwd == null) {
            if (Debug.ON) {
                Debug.trace("challenge pwd is null");
            }
            return false;
        }
        String hashpwd = hashPassword(pwd);

        // got metaInfo
        String challengeString =
                (String) metaInfo.get(CertRecord.META_CHALLENGE_PHRASE);

        if (challengeString == null) {
            if (Debug.ON) {
                Debug.trace("challengeString null");
            }
            return false;
        }

        if (!challengeString.equals(hashpwd)) {
            return false;

            /*
             log(ILogger.LL_FAILURE,
             "Incorrect challenge phrase password used for revocation");
             throw new EInvalidCredentials();
             */
        } else
            return true;
    }

    /**
     * get the list of authentication credential attribute names
     * required by this authentication manager. Generally used by
     * the servlets that handle agent operations to authenticate its
     * users. It calls this method to know which are the
     * required credentials from the user (e.g. Javascript form data)
     *
     * @return attribute names in Vector
     */
    public String[] getRequiredCreds() {
        return (mRequiredCreds);
    }

    /**
     * get the list of configuration parameter names
     * required by this authentication manager. Generally used by
     * the Certificate Server Console to display the table for
     * configuration purposes. ChallengePhraseAuthentication is currently not
     * exposed in this case, so this method is not to be used.
     *
     * @return configuration parameter names in Hashtable of Vectors
     *         where each hashtable entry's key is the substore name, value is a
     *         Vector of parameter names. If no substore, the parameter name
     *         is the Hashtable key itself, with value same as key.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * prepare this authentication manager for shutdown.
     */
    public void shutdown() {
    }

    /**
     * gets the configuretion substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
                level, msg);
    }

    private IRequestQueue getReqQueue() {
        IRequestQueue queue = null;

        try {
            IRegistrationAuthority ra = (IRegistrationAuthority)
                    SubsystemRegistry.getInstance().get("ra");

            if (ra != null) {
                queue = ra.getRequestQueue();
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    " cannot get access to the request queue.");
        }

        return queue;
    }

    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest);

        return "{SHA}" + b64E;
    }
}

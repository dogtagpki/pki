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

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

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
public class ChallengePhraseAuthentication implements AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ChallengePhraseAuthentication.class);

    /* result auth token attributes */
    public static final String TOKEN_CERT_SERIAL = "certSerialToRevoke";

    /* required credentials */
    public static final String CRED_CERT_SERIAL = AuthManager.CRED_CERT_SERIAL_TO_REVOKE;
    public static final String CRED_CHALLENGE = "challengePhrase";
    protected String[] mRequiredCreds = { CRED_CERT_SERIAL, CRED_CHALLENGE };

    /* config parameters to pass to console (none) */
    protected static String[] mConfigParams = null;
    protected ICertificateAuthority mCA = null;
    protected CertificateRepository mCertDB;

    private String mName = null;
    private String mImplName = null;
    private AuthenticationConfig authenticationConfig;
    private AuthManagerConfig mConfig;

    private MessageDigest mSHADigest = null;

    // request attributes hacks
    public static final String CHALLENGE_PHRASE = CRED_CHALLENGE;
    public static final String SUBJECTNAME = "subjectName";
    public static final String SERIALNUMBER = "serialNumber";
    public static final String SERIALNOARRAY = "serialNoArray";

    public ChallengePhraseAuthentication() {
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }

    public void setAuthenticationConfig(AuthenticationConfig authenticationConfig) {
        this.authenticationConfig = authenticationConfig;
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
    @Override
    public void init(String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        try {
            mSHADigest = MessageDigest.getInstance("SHA1");

        } catch (NoSuchAlgorithmException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.getMessage()), e);
        }
    }

    /**
     * Gets the name of this authentication manager.
     */
    @Override
    public String getName() {
        return mName;
    }

    /**
     * Gets the plugin name of authentication manager.
     */
    @Override
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
     * @see org.dogtagpki.server.authentication.AuthToken
     */
    @Override
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        mCA = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);

        if (mCA != null) {
            mCertDB = mCA.getCertificateRepository();
        }

        AuthToken authToken = new AuthToken(this);

        /*
         X509Certificate[] x509Certs =
         (X509Certificate[]) authCred.get(CRED_CERT);
         if (x509Certs == null) {
         logger.error("ChallengePhraseAuthentication: missing cert credential");
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
                        "Invalid serial number"));
            }
        }

        String challenge = (String) authCred.get(CRED_CHALLENGE);

        if (challenge == null) {
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CHALLENGE));
        }
        if (challenge.equals("")) {
            // empty challenge not allowed
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_REVO_ATTEMPT", serialNum.toString()));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        /* maybe later
         if (mCertDB.isCertificateRevoked(cert) != null) {
         logger.error("ChallengePhraseAuthentication: Certificate has already been revoked");
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
                record = mCertDB.readCertificateRecord(serialNum);
            } catch (EBaseException ee) {
                logger.warn("ChallengePhraseAuthentication: " + ee.getMessage(), ee);
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
                                "Invalid password"));

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
            RequestRepository requestRepository = engine.getRequestRepository();
            RequestQueue queue = engine.getRequestQueue();

            if (queue != null) {
                IRequest checkChallengeReq = requestRepository.createRequest(IRequest.REVOCATION_CHECK_CHALLENGE_REQUEST);
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
                    logger.warn(CMS.getLogMessage("CMSCORE_AUTH_INCOMPLETE_REQUEST"));
                }
            } else {
                logger.error(CMS.getLogMessage("CMSCORE_AUTH_FAILED_GET_QUEUE"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_REVOCATION_CHALLENGE_QUEUE_FAILED"));
            }
        } // else, ra
        if (bigIntArray != null && bigIntArray.length > 0) {
            logger.debug("ChallengePhraseAuthentication: challenge authentication serialno array not null");
            for (int i = 0; i < bigIntArray.length; i++)
                logger.debug("ChallengePhraseAuthentication: challenge auth serialno " + bigIntArray[i]);
        }
        logger.debug("ChallengePhraseAuthentication: challenge authentication set " + TOKEN_CERT_SERIAL);
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
            logger.warn("ChallengePhraseAuthentication: challenge pwd is null");
            return false;
        }
        String hashpwd = hashPassword(pwd);

        // got metaInfo
        String challengeString =
                (String) metaInfo.get(CertRecord.META_CHALLENGE_PHRASE);

        if (challengeString == null) {
            logger.warn("ChallengePhraseAuthentication: challengeString null");
            return false;
        }

        if (!challengeString.equals(hashpwd)) {
            return false;

            /*
             logger.error("ChallengePhraseAuthentication: Incorrect challenge phrase password used for revocation");
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
    @Override
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
    @Override
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * prepare this authentication manager for shutdown.
     */
    @Override
    public void shutdown() {
    }

    /**
     * gets the configuretion substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    @Override
    public AuthManagerConfig getConfigStore() {
        return mConfig;
    }

    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest, true);

        return "{SHA}" + b64E;
    }
}

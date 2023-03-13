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
package com.netscape.cms.authentication;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

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
public class ChallengePhraseAuthentication extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ChallengePhraseAuthentication.class);

    /* result auth token attributes */
    public static final String TOKEN_CERT_SERIAL = "certSerialToRevoke";

    /* required credentials */
    public static final String CRED_CERT_SERIAL = AuthManager.CRED_CERT_SERIAL_TO_REVOKE;
    public static final String CRED_CHALLENGE = Request.CHALLENGE_PHRASE;
    protected String[] mRequiredCreds = { CRED_CERT_SERIAL, CRED_CHALLENGE };

    protected CertificateRepository mCertDB;

    private MessageDigest mSHADigest = null;

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
    @Override
    public void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        this.authenticationConfig = authenticationConfig;
        mName = name;
        mImplName = implName;
        mConfig = config;

        try {
            mSHADigest = MessageDigest.getInstance("SHA-256");

        } catch (NoSuchAlgorithmException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.getMessage()), e);
        }
    }

    @Override
    public void init(ConfigStore config) throws EProfileException {
    }

    @Override
    public String getText(Locale locale) {
        return null;
    }

    @Override
    public Enumeration<String> getValueNames() {
        return null;
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public boolean isValueWriteable(String name) {
        return false;
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
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
    public AuthToken authenticate(AuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        CAEngine caEngine = (CAEngine) engine;
        mCertDB = caEngine.getCertificateRepository();

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

        if (bigIntArray != null && bigIntArray.length > 0) {
            logger.debug("ChallengePhraseAuthentication: challenge authentication serialno array not null");
            for (int i = 0; i < bigIntArray.length; i++)
                logger.debug("ChallengePhraseAuthentication: challenge auth serialno " + bigIntArray[i]);
        }
        logger.debug("ChallengePhraseAuthentication: challenge authentication set " + TOKEN_CERT_SERIAL);
        authToken.set(TOKEN_CERT_SERIAL, bigIntArray);

        return authToken;
    }

    @Override
    public void populate(AuthToken token, Request request) throws EProfileException {
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
     * prepare this authentication manager for shutdown.
     */
    @Override
    public void shutdown() {
    }

    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest, true);

        return "{SHA-256}" + b64E;
    }
}

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

import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authentication.RevocationCheckingConfig;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.usrgrp.CertUserLocator;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.ExactMatchCertUserLocator;
import com.netscape.cmscore.usrgrp.User;

/**
 * Certificate server agent authentication.
 * Maps a SSL client authenticate certificate to a user (agent) entry in the
 * internal database.
 * <P>
 *
 * @author lhsiao
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CertUserDBAuthentication extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertUserDBAuthentication.class);

    /* result auth token attributes */
    public final static String TOKEN_USERDN = "user";
    public final static String TOKEN_USER_DN = "userdn";
    public final static String TOKEN_USERID = "userid";
    public final static String TOKEN_UID = "uid";

    /* required credentials */
    public final static String CRED_CERT = AuthManager.CRED_SSL_CLIENT_CERT;

    /* required credentials */
    protected String[] mRequiredCreds = { CRED_CERT };

    private CertUserLocator mCULocator = null;

    private boolean mRevocationCheckingEnabled = false;
    private RevocationCheckingConfig mRevocationChecking;

    public CertUserDBAuthentication() {
    }

    /**
     * initializes the CertUserDBAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing all available authentication managers.
     *
     * @param implName - The authentication subsystem that hosts this
     *            auth manager
     * @param config - The configuration store used by the
     *            authentication subsystem
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

        if (authenticationConfig != null) {
            mRevocationChecking = authenticationConfig.getRevocationCheckingConfig();
        }
        if (mRevocationChecking != null) {
            mRevocationCheckingEnabled = mRevocationChecking.isEnabled();
            if (mRevocationCheckingEnabled) {
                int size = mRevocationChecking.getBufferSize();
                long interval = mRevocationChecking.getValidityInterval();
                long unknownStateInterval = mRevocationChecking.getUnknownStateInterval();

                if (size > 0)
                    engine.setListOfVerifiedCerts(size, interval, unknownStateInterval);
            }
        }

        mCULocator = new ExactMatchCertUserLocator();
        mCULocator.setCMSEngine(engine);
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
     * authenticates user(agent) by certificate
     * <p>
     * called by other subsystems or their servlets to authenticate users (agents)
     *
     * @param authCred - authentication credential that contains
     *            an usrgrp.Certificates of the user (agent)
     * @return the authentication token that contains the following
     *
     * @exception com.netscape.certsrv.base.EAuthsException any
     *                authentication failure or insufficient credentials
     * @see org.dogtagpki.server.authentication.AuthToken
     * @see com.netscape.certsrv.usrgrp.Certificates
     */
    @Override
    public AuthToken authenticate(AuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {
        logger.debug("CertUserDBAuth: started");
        AuthToken authToken = new AuthToken(this);
        logger.debug("CertUserDBAuth: Retrieving client certificate");
        X509Certificate[] x509Certs =
                (X509Certificate[]) authCred.get(CRED_CERT);

        if (x509Certs == null) {
            logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_MISSING_CERT"));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CERT));
        }
        logger.debug("CertUserDBAuth: Got client certificate");

        if (mRevocationCheckingEnabled) {
            X509CertImpl cert0 = (X509CertImpl) x509Certs[0];
            if (cert0 == null) {
                logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_NO_CERT"));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_NO_CERT"));
            }

            if (engine.isRevoked(x509Certs)) {
                logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_REVOKED_CERT"));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        }

        logger.debug("Authentication: client certificate found");

        // map cert to user
        User user = null;
        Certificates certs = new Certificates(x509Certs);

        try {
            user = mCULocator.locateUser(certs);
        } catch (EUsrGrpException e) {
            logger.error("CertUserDBAuthentication: cannot map certificate to any user: " + e.getMessage(), e);
            logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_AGENT_AUTH_FAILED", x509Certs[0].getSerialNumber()
                    .toString(16), x509Certs[0].getSubjectDN().toString(), e.toString()));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        } catch (netscape.ldap.LDAPException e) {
            logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_CANNOT_AGENT_AUTH", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        // any unexpected error occurs like internal db down,
        // UGSubsystem only returns null for user.
        if (user == null) {
            logger.error("CertUserDBAuthentication: cannot map certificate to any user");
            logger.error("CertUserDBAuthentication: " + CMS.getLogMessage("CMSCORE_AUTH_AGENT_USER_NOT_FOUND"));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        logger.debug("Authentication: mapped certificate to user");

        authToken.set(TOKEN_USERDN, user.getUserDN());
        authToken.set(TOKEN_USER_DN, user.getUserDN());
        authToken.set(TOKEN_USERID, user.getUserID());
        authToken.set(TOKEN_UID, user.getUserID());
        authToken.set(CRED_CERT, certs);

        logger.info("CertUserDBAuthentication: " + CMS.getLogMessage("CMS_AUTH_AUTHENTICATED", user.getUserID()));

        return authToken;
    }

    @Override
    public void populate(AuthToken token, Request request) throws EProfileException {
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
}

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
// (C) 2008 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.authentication;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.ISSLClientCertProvider;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * Certificate server SSL client authentication.
 *
 * @author Christina Fu
 *         <P>
 *
 */
public class SSLclientCertAuthentication extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SSLclientCertAuthentication.class);

    /* result auth token attributes */
    public static final String TOKEN_USERDN = "user";
    public static final String TOKEN_USER_DN = "userdn";
    public static final String TOKEN_USERID = "userid";
    public static final String TOKEN_UID = "uid";

    /* required credentials */
    public static final String CRED_CERT = AuthManager.CRED_SSL_CLIENT_CERT;
    protected String[] mRequiredCreds = { CRED_CERT };

    public SSLclientCertAuthentication() {
    }

    /**
     * initializes the SSLClientCertAuthentication auth manager
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
    }

    @Override
    public boolean isSSLClientRequired() {
        return true;
    }

    /**
     * authenticates user by certificate
     * <p>
     * called by other subsystems or their servlets to authenticate users
     *
     * @param authCred - authentication credential that contains
     *            an usrgrp.Certificates of the user (agent)
     * @return the authentication token that contains the following
     *
     * @exception EMissingCredential If a required credential for this
     *                authentication manager is missing.
     * @exception EInvalidCredentials If credentials cannot be authenticated.
     * @exception EBaseException If an internal error occurred.
     * @see org.dogtagpki.server.authentication.AuthToken
     * @see com.netscape.certsrv.usrgrp.Certificates
     */
    @Override
    public AuthToken authenticate(AuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        logger.debug("SSLclientCertAuthentication: start");
        logger.debug("authenticator instance name is " + getName());

        // force SSL handshake
        SessionContext context = SessionContext.getExistingContext();
        ISSLClientCertProvider provider = (ISSLClientCertProvider)
                context.get("sslClientCertProvider");

        if (provider == null) {
            logger.error("SSLclientCertAuthentication: No SSL Client Cert Provider Found");
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        logger.debug("SSLclientCertAuthentication: got provider");
        logger.debug("SSLclientCertAuthentication: retrieving client certificate");
        X509Certificate[] allCerts = provider.getClientCertificateChain();

        if (allCerts == null) {
            logger.error("SSLclientCertAuthentication: No SSL Client Certs Found");
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        logger.debug("SSLclientCertAuthentication: got certificates");

        // retreive certificate from socket
        AuthToken authToken = new AuthToken(this);
        X509Certificate[] x509Certs = allCerts;

        // default certificate default has bugs in version
        // version(3) is returned as 3, which should be 2
        X509CertImpl ci[] = new X509CertImpl[x509Certs.length];

        X509Certificate clientCert = null;
        try {
            for (int i = 0; i < x509Certs.length; i++) {
                ci[i] = new X509CertImpl(x509Certs[i].getEncoded());
                // find out which one is the leaf cert
                clientCert = ci[i];

                byte[] extBytes = clientCert.getExtensionValue("2.5.29.19");
                // try to see if this is a leaf cert
                // look for BasicConstraint extension
                if (extBytes == null) {
                    // found leaf cert
                    logger.debug("SSLclientCertAuthentication: authenticate: found leaf cert");
                    break;
                } else {
                    logger.debug("SSLclientCertAuthentication: authenticate: found cert having BasicConstraints ext");
                    // it's got BasicConstraints extension
                    // so it's not likely to be a leaf cert,
                    // however, check the isCA field regardless
                    try {
                        BasicConstraintsExtension bce =
                                new BasicConstraintsExtension(true, extBytes);
                        if (bce != null) {
                            if (!(Boolean) bce.get("is_ca")) {
                                logger.debug("SSLclientCertAuthentication: authenticate: found CA cert in chain");
                                break;
                            } // else found a ca cert, continue
                        }
                    } catch (Exception e) {
                        logger.error("SSLclientCertAuthentication: authenticate: exception: " + e.getMessage(), e);
                        throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"), e);
                    }
                }
            }
            if (clientCert == null) {
                logger.error("SSLclientCertAuthentication: authenticate: client cert not found");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        } catch (CertificateException e) {
            logger.error("SSLclientCertAuthentication: " + e.getMessage(), e);
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"), e);
        }

        // check if certificate(s) is revoked
        boolean checkRevocation = true;
        try {
            checkRevocation = mConfig.getBoolean("checkRevocation", true);
        } catch (EBaseException e) {
            // do nothing; default to true
        }
        if (checkRevocation) {
            if (engine.isRevoked(ci)) {
                logger.error("SSLclientCertAuthentication: certificate revoked");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        }
        Certificates certs = new Certificates(ci);
        Principal p_dn = clientCert.getSubjectDN();
        authToken.set(TOKEN_USERDN, p_dn.getName());
        authToken.set("userdn", p_dn.getName());
        String uid = getUidFromDN(p_dn.getName());
        if (uid != null) {
            authToken.set(TOKEN_UID, uid);
            authToken.set(TOKEN_USERID, uid);
        }
        /*
                authToken.set(TOKEN_USER_DN, user.getUserDN());
                authToken.set(TOKEN_USERID, user.getUserID());
                authToken.set(TOKEN_UID, user.getUserID());
                authToken.set(TOKEN_GROUP, groupname);
        */
        authToken.set(CRED_CERT, certs);

        logger.debug("SSLclientCertAuthentication: authenticated ");

        return authToken;
    }

    String getUidFromDN(String userdn) {
        StringTokenizer st = new StringTokenizer(userdn, ",");
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            int i = t.indexOf("=");

            if (i == -1) {
                continue;
            }
            String n = t.substring(0, i);
            if (n.equalsIgnoreCase("uid")) {
                String v = t.substring(i + 1);
                logger.debug("SSLclientCertAuthentication: getUidFromDN(): uid found:" + v);
                return v;
            } else {
                continue;
            }
        }
        return null;
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

    // Profile-related methods

    @Override
    public void init(ConfigStore config) throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_SSL_CLIENT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_SSL_CLIENT_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        return null;
    }

    @Override
    public boolean isValueWriteable(String name) {
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void populate(AuthToken token, Request request)
            throws EProfileException {
        request.setExtData(AuthManager.AUTHENTICATED_NAME,
                token.getInString(TOKEN_USERDN));
        request.setExtData(AuthManager.AUTHENTICATED_NAME,
                token.getInString("userDN"));
    }
}

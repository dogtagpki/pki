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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthManagersConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authentication.IAuthManager;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ISSLClientCertProvider;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.ICertUserLocator;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.profile.IProfileAuthenticator;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;

/**
 * Certificate server agent authentication.
 * Maps a SSL client authenticate certificate to a user (agent) entry in the
 * internal database.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class AgentCertAuthentication implements IAuthManager,
        IProfileAuthenticator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AgentCertAuthentication.class);

    /* required credentials */
    public static final String CRED_CERT = IAuthManager.CRED_SSL_CLIENT_CERT;
    protected String[] mRequiredCreds = { CRED_CERT };

    /* config parameters to pass to console (none) */
    protected static String[] mConfigParams = null;

    private String mName = null;
    private String mImplName = null;
    private AuthManagerConfig mConfig;

    private UGSubsystem mUGSub = null;
    private ICertUserLocator mCULocator = null;

    public AgentCertAuthentication() {
    }

    /**
     * initializes the CertUserDBAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing all available authentication managers.
     *
     * @param name The name of this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config The configuration store for this authentication manager.
     */
    public void init(String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        CMSEngine engine = CMS.getCMSEngine();
        mUGSub = (UGSubsystem) engine.getSubsystem(UGSubsystem.ID);
        mCULocator = mUGSub.getCertUserLocator();
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

    public boolean isSSLClientRequired() {
        return true;
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
     * @exception EMissingCredential If a required credential for this
     *                authentication manager is missing.
     * @exception EInvalidCredentials If credentials cannot be authenticated.
     * @exception EBaseException If an internal error occurred.
     * @see org.dogtagpki.server.authentication.AuthToken
     * @see com.netscape.certsrv.usrgrp.Certificates
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        logger.debug("AgentCertAuthentication: start");
        logger.debug("authenticator instance name is " + getName());

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig sconfig = engine.getConfig();
        AuthenticationConfig authsConfig = sconfig.getAuthenticationConfig();
        AuthManagersConfig instancesConfig = authsConfig.getAuthManagersConfig();

        // force SSL handshake
        SessionContext context = SessionContext.getExistingContext();
        ISSLClientCertProvider provider = (ISSLClientCertProvider)
                context.get("sslClientCertProvider");

        if (provider == null) {
            logger.error("AgentCertAuthentication: No SSL Client Cert Provider Found");
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        logger.debug("AgentCertAuthenticator: got provider");
        logger.debug("AgentCertAuthenticator: retrieving client certificate");
        X509Certificate[] allCerts = provider.getClientCertificateChain();

        if (allCerts == null) {
            logger.error("AgentCertAuthentication: No SSL Client Certs Found");
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        logger.debug("AgentCertAuthenticator: got certificates");

        // retreive certificate from socket
        AuthToken authToken = new AuthToken(this);
        X509Certificate[] x509Certs = allCerts;

        // default certificate default has bugs in version
        // version(3) is returned as 3, which should be 2
        X509CertImpl ci[] = new X509CertImpl[x509Certs.length];

        try {
            for (int i = 0; i < x509Certs.length; i++) {
                ci[i] = new X509CertImpl(x509Certs[i].getEncoded());
            }
        } catch (CertificateException e) {
            logger.warn("Unable to parse certificate: " + e.getMessage(), e);
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
                logger.error("AgentCertAuthentication: certificate revoked");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        }

        // map cert to user
        IUser user = null;
        Certificates certs = new Certificates(ci);

        try {
            user = mCULocator.locateUser(certs);
        } catch (EUsrGrpException e) {
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"), e);
        } catch (netscape.ldap.LDAPException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        e.toString()));
        }

        // any unexpected error occurs like internal db down,
        // UGSubsystem only returns null for user.
        if (user == null) {
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        // get group name from configuration file
        String groupname = "";
        try {
            groupname = instancesConfig.getString(getName() + ".agentGroup", "");
        } catch (EBaseException ee) {
        }

        if (!groupname.equals("")) {
            logger.debug("check if " + user.getUserID() + " is  in group " + groupname);
            UGSubsystem uggroup = (UGSubsystem) engine.getSubsystem(UGSubsystem.ID);
            if (!uggroup.isMemberOf(user, groupname)) {
                logger.error(user.getUserID() + " is not in this group " + groupname);
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHORIZATION_ERROR"));
            }
        }
        authToken.set(IAuthToken.USER, user.getUserDN());
        authToken.set(IAuthToken.USER_DN, user.getUserDN());
        authToken.set(IAuthToken.USER_ID, user.getUserID());
        authToken.set(IAuthToken.UID, user.getUserID());
        authToken.set(IAuthToken.GROUP, groupname);
        authToken.set(CRED_CERT, certs);

        logger.info("AgentCertAuthentication: authenticated " + user.getUserDN());

        return authToken;
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
     * configuration purposes. CertUserDBAuthentication is currently not
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
     * gets the configuration substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    public AuthManagerConfig getConfigStore() {
        return mConfig;
    }

    // Profile-related methods

    public void init(Profile profile, IConfigStore config)
            throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        return null;
    }

    public boolean isValueWriteable(String name) {
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public void populate(IAuthToken token, IRequest request)
            throws EProfileException {
    }
}

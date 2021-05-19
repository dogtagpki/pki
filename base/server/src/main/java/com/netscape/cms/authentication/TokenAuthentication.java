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

import java.io.ByteArrayInputStream;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.ProfileAuthenticator;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Token authentication.
 * Checked if the given token is valid.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class TokenAuthentication implements ProfileAuthenticator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TokenAuthentication.class);

    /* required credentials */
    public static final String CRED_SESSION_ID = AuthManager.CRED_SESSION_ID;
    protected String[] mRequiredCreds = { CRED_SESSION_ID };

    /* config parameters to pass to console (none) */
    protected static String[] mConfigParams = null;

    private String mName = null;
    private String mImplName = null;
    private AuthManagerConfig mConfig;

    public TokenAuthentication() {
    }

    /**
     * initializes the TokenAuthentication auth manager
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
     * @exception EMissingCredential If a required credential for this
     *                authentication manager is missing.
     * @exception EInvalidCredentials If credentials cannot be authenticated.
     * @exception EBaseException If an internal error occurred.
     * @see org.dogtagpki.server.authentication.AuthToken
     * @see com.netscape.certsrv.usrgrp.Certificates
     */
    @Override
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        logger.debug("TokenAuthentication: start");

        CMSEngine engine = CMS.getCMSEngine();

        // force SSL handshake
        SessionContext context = SessionContext.getExistingContext();

        // retreive certificate from socket
        AuthToken authToken = new AuthToken(this);

        // get group name from configuration file
        EngineConfig sconfig = engine.getConfig();

        String sessionId = (String) authCred.get(CRED_SESSION_ID);
        String givenHost = (String) authCred.get("clientHost");
        String authHost = sconfig.getString("securitydomain.host");
        int authAdminPort = sconfig.getInteger("securitydomain.httpsadminport");
        String authPath = "/ca/admin/ca/tokenAuthenticate";

        String authURL = "https://" + authHost + ":" + authAdminPort + authPath;
        logger.info("TokenAuthentication: Authenticating session ID against security domain at " + authURL);

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle(CRED_SESSION_ID, sessionId);
        content.putSingle("hostname", givenHost);
        logger.debug("TokenAuthentication: content: " + content);

        String c = null;
        try {
            c = sendAuthRequest(authHost, authAdminPort, authPath, content);
            // in case where the new interface does not exist, EE will return a badly
            // formatted response which will throw an exception during parsing
            if (c != null) {
                @SuppressWarnings("unused")
                XMLObject parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));
            }

        } catch (Exception e) {
            String message = "Unable to access security domain: " + e.getMessage();
            logger.error(message, e);
            throw new EBaseException(message, e);
        }

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    logger.error("TokenAuthentication::authenticate() - "
                             + "Exception=" + e.getMessage(), e);
                    throw new EBaseException(e.toString());
                }
                String status = parser.getValue("Status");

                logger.debug("TokenAuthentication: status=" + status);
                if (!status.equals("0")) {
                    String error = parser.getValue("Error");
                    logger.error("TokenAuthentication: error: " + error);
                    throw new EBaseException(error);
                }

                String uid = parser.getValue("uid");
                String gid = parser.getValue("gid");
                String[] groups = {gid};

                authToken.set(IAuthToken.UID, uid);
                authToken.set(IAuthToken.GROUPS, groups);

                if (context != null) {
                    logger.debug("SessionContext.USER_ID " + uid + " SessionContext.GROUP_ID " + gid);
                    context.put(SessionContext.USER_ID, uid);
                    context.put(SessionContext.GROUP_ID, gid);
                }

                logger.debug("TokenAuthentication: authenticated uid=" + uid + ", gid=" + gid);
            } catch (EBaseException e) {
                throw e;
            } catch (Exception e) {
            }
        }

        return authToken;
    }

    private String sendAuthRequest(String authHost, int authPort, String authUrl, MultivaluedMap<String, String> content)
            throws Exception {

        String serverURL = "https://" + authHost + ":" + authPort;
        PKIClient client = Configurator.createClient(serverURL, null, null);
        return client.post(authUrl, content, String.class);
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
     * configuration purposes. CertUserDBAuthentication is currently not
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

    // Profile-related methods

    @Override
    public void init(Profile profile, IConfigStore config)
            throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CRED_SESSION_ID);
        return v.elements();
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
    public void populate(IAuthToken token, IRequest request)
            throws EProfileException {
    }
}

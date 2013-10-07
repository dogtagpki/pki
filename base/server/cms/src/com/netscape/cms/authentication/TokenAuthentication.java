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
import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Token authentication.
 * Checked if the given token is valid.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class TokenAuthentication implements IAuthManager,
        IProfileAuthenticator {

    /* result auth token attributes */
    public static final String TOKEN_UID = "uid";
    public static final String TOKEN_GID = "gid";

    /* required credentials */
    public static final String CRED_SESSION_ID = IAuthManager.CRED_SESSION_ID;
    protected String[] mRequiredCreds = { CRED_SESSION_ID };

    /* config parameters to pass to console (none) */
    protected static String[] mConfigParams = null;

    private String mName = null;
    private String mImplName = null;
    private IConfigStore mConfig = null;

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
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;
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
     * @see com.netscape.certsrv.authentication.AuthToken
     * @see com.netscape.certsrv.usrgrp.Certificates
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        CMS.debug("TokenAuthentication: start");

        // force SSL handshake
        SessionContext context = SessionContext.getExistingContext();

        // retreive certificate from socket
        AuthToken authToken = new AuthToken(this);

        // get group name from configuration file
        IConfigStore sconfig = CMS.getConfigStore();

        String sessionId = (String) authCred.get(CRED_SESSION_ID);
        String givenHost = (String) authCred.get("clientHost");
        String authHost = sconfig.getString("securitydomain.host");
        int authAdminPort = sconfig.getInteger("securitydomain.httpsadminport");
        int authEEPort = sconfig.getInteger("securitydomain.httpseeport");
        String authURL = "/ca/admin/ca/tokenAuthenticate";

        String content = CRED_SESSION_ID + "=" + sessionId + "&hostname=" + givenHost;
        CMS.debug("TokenAuthentication: content=" + content);

        String c = null;
        try {
            c = sendAuthRequest(authHost, authAdminPort, authURL, content);
            // in case where the new interface does not exist, EE will return a badly
            // formatted response which will throw an exception during parsing
            if (c != null) {
                @SuppressWarnings("unused")
                XMLObject parser = new XMLObject(new ByteArrayInputStream(c.getBytes()));
            }
        } catch (Exception e) {

            CMS.debug("TokenAuthenticate: failed to contact admin host:port "
                    + authHost + ":" + authAdminPort + " " + e);
            CMS.debug("TokenAuthenticate: attempting ee port " + authEEPort);
            authURL = "/ca/ee/ca/tokenAuthenticate";
            try {
                c = sendAuthRequest(authHost, authEEPort, authURL, content);
            } catch (IOException e1) {
                CMS.debug("TokenAuthenticate: failed to contact EE host:port "
                        + authHost + ":" + authAdminPort + " " + e1);
                throw new EBaseException(e1.getMessage());
            }
        }

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug("TokenAuthentication::authenticate() - "
                             + "Exception=" + e.toString());
                    throw new EBaseException(e.toString());
                }
                String status = parser.getValue("Status");

                CMS.debug("TokenAuthentication: status=" + status);
                if (!status.equals("0")) {
                    String error = parser.getValue("Error");
                    throw new EBaseException(error);
                }

                String uid = parser.getValue("uid");
                String gid = parser.getValue("gid");

                authToken.set(TOKEN_UID, uid);
                authToken.set(TOKEN_GID, gid);

                if (context != null) {
                    CMS.debug("SessionContext.USER_ID " + uid + " SessionContext.GROUP_ID " + gid);
                    context.put(SessionContext.USER_ID, uid);
                    context.put(SessionContext.GROUP_ID, gid);
                }

                CMS.debug("TokenAuthentication: authenticated uid=" + uid + ", gid=" + gid);
            } catch (EBaseException e) {
                throw e;
            } catch (Exception e) {
            }
        }

        return authToken;
    }

    private String sendAuthRequest(String authHost, int authPort, String authUrl, String content)
            throws IOException {
        HttpClient httpclient = new HttpClient();
        String c = null;

        JssSSLSocketFactory factory = new JssSSLSocketFactory();
        httpclient = new HttpClient(factory);
        httpclient.connect(authHost, authPort);
        HttpRequest httprequest = new HttpRequest();
        httprequest.setMethod(HttpRequest.POST);
        httprequest.setURI(authUrl);
        httprequest.setHeader("user-agent", "HTTPTool/1.0");
        httprequest.setHeader("content-length", "" + content.length());
        httprequest.setHeader("content-type",
                "application/x-www-form-urlencoded");
        httprequest.setContent(content);

        HttpResponse httpresponse = httpclient.send(httprequest);
        c = httpresponse.getContent();

        return c;
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
     * gets the configuretion substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    // Profile-related methods

    public void init(IProfile profile, IConfigStore config)
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
        Vector<String> v = new Vector<String>();

        v.addElement(CRED_SESSION_ID);
        return v.elements();
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

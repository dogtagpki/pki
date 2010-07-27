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

import java.io.*;
import java.util.*;
import java.lang.Class;
import java.security.cert.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.policy.*;
import com.netscape.cmsutil.http.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.ra.*;
import com.netscape.certsrv.kra.*;
import javax.servlet.http.HttpServletRequest;
import com.netscape.cmsutil.xml.*;
import org.w3c.dom.*;

/**
 * Token authentication.  
 * Checked if the given token is valid.
 * <P>
 *
 * @version $Revision: 6081 $, $Date: 2004-01-29 10:42:22 -0800 (Thu, 29 Jan 2004) $
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

    private IUGSubsystem mUGSub = null;
    private ILogger mLogger = CMS.getLogger();

    public TokenAuthentication() {
    }

    /**
     * initializes the TokenAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing
     * all available authentication managers.
     * @param name The name of this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config The configuration store for this authentication manager.
     */
    public void init(String name, String implName, IConfigStore config)
        throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        mUGSub = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
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
     * called by other subsystems or their servlets to authenticate
     *	 users (agents)
     * @param authCred - authentication credential that contains
     *	 an usrgrp.Certificates of the user (agent)
     * @return the authentication token that contains the following
     * @exception EMissingCredential If a required credential for this 
     * authentication manager is missing.
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

        String sessionId = (String)authCred.get(CRED_SESSION_ID);
        String givenHost = (String)authCred.get("clientHost");
        String auth_host = sconfig.getString("securitydomain.host");
        int auth_port = sconfig.getInteger("securitydomain.httpseeport");

        HttpClient httpclient = new HttpClient();
        String c = null;
        try {
            JssSSLSocketFactory factory = new JssSSLSocketFactory();
            httpclient = new HttpClient(factory);
            String content = CRED_SESSION_ID+"="+sessionId+"&hostname="+givenHost;
            CMS.debug("TokenAuthentication: content=" + content);
            httpclient.connect(auth_host, auth_port);
            HttpRequest httprequest = new HttpRequest();
            httprequest.setMethod(HttpRequest.POST);
            httprequest.setURI("/ca/ee/ca/tokenAuthenticate");
            httprequest.setHeader("user-agent", "HTTPTool/1.0");
            httprequest.setHeader("content-length", "" + content.length());
            httprequest.setHeader("content-type",
                    "application/x-www-form-urlencoded");
            httprequest.setContent(content);
            HttpResponse httpresponse = httpclient.send(httprequest);

            c = httpresponse.getContent();
        } catch (Exception e) { 
            CMS.debug("TokenAuthentication authenticate Exception="+e.toString());
        }

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "TokenAuthentication::authenticate() - "
                             + "Exception="+e.toString() );
                    throw new EBaseException( e.toString() );
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

                if(context != null)  {
                    CMS.debug("SessionContext.USER_ID " + uid + " SessionContext.GROUP_ID " + gid);
                    context.put(SessionContext.USER_ID,  uid );
                    context.put(SessionContext.GROUP_ID, gid );
                }

                CMS.debug("TokenAuthentication: authenticated uid="+uid+", gid="+gid);
            } catch (EBaseException e) {
                throw e;
            } catch (Exception e) {
            }
        }

        return authToken;
    }

    /**
     * get the list of authentication credential attribute names
     *	 required by this authentication manager. Generally used by
     *	 the servlets that handle agent operations to authenticate its
     *	 users.  It calls this method to know which are the
     *	 required credentials from the user (e.g. Javascript form data)
     * @return attribute names in Vector
     */
    public String[] getRequiredCreds() {
        return (mRequiredCreds);
    }

    /**
     * get the list of configuration parameter names
     *	 required by this authentication manager.  Generally used by
     *	 the Certificate Server Console to display the table for
     *	 configuration purposes.  CertUserDBAuthentication is currently not
     *	 exposed in this case, so this method is not to be used.
     * @return configuration parameter names in Hashtable of Vectors
     *	 where each hashtable entry's key is the substore name, value is a
     * Vector of parameter names.  If no substore, the parameter name
     *	 is the Hashtable key itself, with value same as key.
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
     *  manager
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
    public Enumeration getValueNames() {
        Vector v = new Vector();

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

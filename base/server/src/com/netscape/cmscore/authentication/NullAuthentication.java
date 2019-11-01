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

import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authentication.IAuthManager;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;

/**
 * This authentication does nothing but just returns an empty authToken.
 * <P>
 *
 * @author chrisho
 * @version $Revision$, $Date$
 */
public class NullAuthentication implements IAuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NullAuthentication.class);

    /* configuration params to pass to console (none) */
    protected static String[] mConfigParams = null;

    protected static String[] mRequiredCred = {};
    private String mName = null;
    private String mImplName = null;
    private AuthenticationConfig authenticationConfig;
    private AuthManagerConfig mConfig;

    public NullAuthentication() {
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }

    public void setAuthenticationConfig(AuthenticationConfig authenticationConfig) {
        this.authenticationConfig = authenticationConfig;
    }

    /**
     * initializes the NullAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing all available authentication managers.
     *
     * @param name - Name assigned to this authentication manager instance.
     * @param implName - Name of the authentication plugin.
     * @param config - The configuration store used by the
     *            authentication subsystem.
     */
    public void init(String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        logger.info(CMS.getLogMessage("CMSCORE_AUTH_INIT_AUTH", mName));
    }

    /**
     * authenticates nothing
     * <p>
     * called by other subsystems or their servlets to authenticate administrators
     *
     * @param authCred Authentication credentials.
     *            "uid" and "pwd" are required.
     * @return the authentication token (authToken) that contains the following
     *         userdn = [userdn, in case of success]<br>
     *         authMgrName = [authMgrName]<br>
     * @exception com.netscape.certsrv.base.MissingCredential If either
     *                "uid" or "pwd" is missing from the given credentials.
     * @exception com.netscape.certsrv.base.InvalidCredentials If the
     *                the credentials failed to authenticate.
     * @exception com.netscape.certsrv.base.EBaseException If an internal
     *                error occurred.
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {
        AuthToken authToken = new AuthToken(this);

        authToken.set("authType", "NOAUTH");

        return authToken;
    }

    /**
     * gets the name of this authentication manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the name of the authentication manager plugin
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * get the list of authentication credential attribute names
     * required by this authentication manager. Generally used by
     * servlets that use this authentication manager, to retrieve
     * required credentials from the user (e.g. Javascript form data)
     *
     * @return attribute names in Vector
     */
    public String[] getRequiredCreds() {
        return (mRequiredCred);
    }

    /**
     * Get the list of configuration parameter names
     * required by this authentication manager. In this case, an empty list.
     *
     * @return String array of configuration parameters.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * disconnects the member connection
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
}

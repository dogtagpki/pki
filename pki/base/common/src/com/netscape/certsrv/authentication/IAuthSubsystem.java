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
package com.netscape.certsrv.authentication;

import com.netscape.certsrv.base.*;
import java.util.*;

/**
 * An interface that represents an authentication component
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IAuthSubsystem extends ISubsystem {

    /**
     * Constant for auths.
     */
    public static final String ID = "auths";

    /**
     * Constant for class.
     */
    public static final String PROP_CLASS = "class"; 

    /**
     * Constant for impl
     */
    public static final String PROP_IMPL = "impl"; 

    /**
     * Constant for pluginName.
     */
    public static final String PROP_PLUGIN = "pluginName"; 

    /**
     * Constant for instance.
     */
    public static final String PROP_INSTANCE = "instance";

    /* XXX should not be here */

    /**
     * Constant for password based authentication plugin ID.
     */
    public static final String PASSWDUSERDB_PLUGIN_ID = "passwdUserDBAuthPlugin";

    /**
     * Constant for certificate based authentication plugin ID.
     */
    public static final String CERTUSERDB_PLUGIN_ID = "certUserDBAuthPlugin";

    /**
     * Constant for challenge based authentication plugin ID.
     */
    public static final String CHALLENGE_PLUGIN_ID = "challengeAuthPlugin";

    /**
     * Constant for null authentication plugin ID.
     */
    public static final String NULL_PLUGIN_ID = "nullAuthPlugin";

    /**
     * Constant for ssl client authentication plugin ID.
     */
    public static final String SSLCLIENTCERT_PLUGIN_ID = "sslClientCertAuthPlugin";

    /**
     * Constant for password based authentication manager ID.
     */
    public static final String PASSWDUSERDB_AUTHMGR_ID = "passwdUserDBAuthMgr";

    /**
     * Constant for certificate based authentication manager ID.
     */
    public static final String CERTUSERDB_AUTHMGR_ID = "certUserDBAuthMgr";

    /**
     * Constant for challenge based authentication manager ID.
     */
    public static final String CHALLENGE_AUTHMGR_ID = "challengeAuthMgr";

    /**
     * Constant for null authentication manager ID.
     */
    public static final String NULL_AUTHMGR_ID = "nullAuthMgr";

    /**
     * Constant for ssl client authentication manager ID.
     */
    public static final String SSLCLIENTCERT_AUTHMGR_ID = "sslClientCertAuthMgr";

    /**
     * Constant for CMC authentication plugin ID.
     */
    public static final String CMCAUTH_PLUGIN_ID = "CMCAuth";

    /**
     * Constant for CMC authentication manager ID.
     */
    public static final String CMCAUTH_AUTHMGR_ID = "CMCAuth";

    /**
     * Authenticate the given credentials using the given manager name.
     * @param authCred The authentication credentials
     * @param authMgrName The authentication manager name
     * @return a authentication token.
     * @exception EMissingCredential when missing credential during authentication
     * @exception EInvalidCredentials when the credential is invalid
     * @exception EBaseException If an error occurs during authentication.
     */
    public IAuthToken authenticate(IAuthCredentials authCred, String authMgrName)
        throws EMissingCredential, EInvalidCredentials, EBaseException;

    /**
     * Gets the required credential attributes for the given authentication
     * manager.
     * @param authMgrName The authentication manager name
     * @return a Vector of required credential attribute names.
     * @exception EBaseException If the required credential is missing
     */
    public String[] getRequiredCreds(String authMgrName) throws EBaseException;

    /**
     * Adds (registers) the given authentication manager.
     * @param name The authentication manager name
     * @param authMgr The authentication manager instance.
     */
    public void add(String name, IAuthManager authMgr);

    /**
     * Deletes (deregisters) the given authentication manager.
     * @param name The authentication manager name to delete.
     */
    public void delete(String name);

    /**
     * Gets the Authentication manager instance of the specified name.
     * @param name The authentication manager's name.
     * @exception EBaseException when internal error occurs.
     */
    public IAuthManager getAuthManager(String name) throws EBaseException;

    /**
     * Gets an enumeration of authentication managers registered to the
     * authentication subsystem.
     * @return a list of authentication managers
     */
    public Enumeration getAuthManagers();

    /**
     * Gets an enumeration of authentication manager plugins.
     * @return a list of authentication plugins
     */
    public Enumeration getAuthManagerPlugins();

    /**
     * Gets a single authentication manager plugin implementation
     * @param name given authentication plugin name
     * @return the given authentication plugin
     */
    public IAuthManager getAuthManagerPlugin(String name);

    /**
     * Get configuration parameters for a authentication mgr plugin.
     * @param implName The plugin name.
     * @return configuration parameters for the given authentication manager plugin
     * @exception EAuthMgrPluginNotFound If the authentication manager 
     * plugin is not found.
     * @exception EBaseException If an internal error occurred.
     */
    public String[] getConfigParams(String implName) 
        throws EAuthMgrPluginNotFound, EBaseException;

    /**
     * Log error message.
     * @param level log level
     * @param msg error message
     */
    public void log(int level, String msg);

    /**
     * Get a hashtable containing all authentication plugins.
     * @return all authentication plugins.
     */
    public Hashtable getPlugins();

    /**
     * Get a hashtable containing all authentication instances.
     * @return all authentication instances.
     */
    public Hashtable getInstances();

    /**
     * Get an authentication manager interface for the given name.
     * @param name given authentication manager name.
     * @return an authentication manager for the given manager name.
     */
    public IAuthManager get(String name);

    /**
     * Get an authentication manager plugin impl  for the given name.
     * @param name given authentication manager name.
     * @return an authentication manager plugin
     */
    public AuthMgrPlugin getAuthManagerPluginImpl(String name);
}


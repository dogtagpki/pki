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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthManagerProxy;
import org.dogtagpki.server.authentication.AuthManagersConfig;
import org.dogtagpki.server.authentication.AuthenticationConfig;

import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthMgrNotFound;
import com.netscape.certsrv.authentication.EAuthMgrPluginNotFound;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cms.authentication.CMCAuth;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * Default authentication subsystem
 * <P>
 *
 * @author cfu
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class AuthSubsystem implements ISubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthSubsystem.class);

    public final static String ID = "auths";

    public final static String PROP_CLASS = "class";
    public final static String PROP_IMPL = "impl";
    public final static String PROP_PLUGIN = "pluginName";

    /**
     * Constant for password based authentication plugin ID.
     */
    public final static String PASSWDUSERDB_PLUGIN_ID = "passwdUserDBAuthPlugin";

    /**
     * Constant for certificate based authentication plugin ID.
     */
    public final static String CERTUSERDB_PLUGIN_ID = "certUserDBAuthPlugin";

    /**
     * Constant for challenge based authentication plugin ID.
     */
    public final static String CHALLENGE_PLUGIN_ID = "challengeAuthPlugin";

    /**
     * Constant for null authentication plugin ID.
     */
    public final static String NULL_PLUGIN_ID = "nullAuthPlugin";

    /**
     * Constant for ssl client authentication plugin ID.
     */
    public final static String SSLCLIENTCERT_PLUGIN_ID = "sslClientCertAuthPlugin";

    /**
     * Constant for password based authentication manager ID.
     */
    public final static String PASSWDUSERDB_AUTHMGR_ID = "passwdUserDBAuthMgr";

    /**
     * Constant for certificate based authentication manager ID.
     */
    public final static String CERTUSERDB_AUTHMGR_ID = "certUserDBAuthMgr";

    /**
     * Constant for null authentication manager ID.
     */
    public final static String NULL_AUTHMGR_ID = "nullAuthMgr";

    /**
     * Constant for ssl client authentication manager ID.
     */
    public final static String SSLCLIENTCERT_AUTHMGR_ID = "sslClientCertAuthMgr";

    /**
     * Constant for CMC authentication plugin ID.
     */
    public final static String CMCAUTH_PLUGIN_ID = "CMCAuth";

    /**
     * Constant for CMC authentication manager ID.
     */
    public final static String CMCAUTH_AUTHMGR_ID = "CMCAuth";

    /**
     * Constant for CMC user-signed authentication manager ID.
     */
    public final static String CMC_USER_SIGNED_AUTH_AUTHMGR_ID = "CMCUserSignedAuth";

    public Hashtable<String, AuthMgrPlugin> mAuthMgrPlugins = new Hashtable<>();
    public Hashtable<String, AuthManagerProxy> mAuthMgrInsts = new Hashtable<>();
    private String mId = "auths";
    private AuthenticationConfig mConfig;

    public AuthSubsystem() {
    }

    public void loadAuthManagerPlugins() throws EBaseException {

        // hardcode admin and agent plugins required for the server to be
        // functional.

        logger.info("AuthSubsystem: Loading auth manager plugin " + PASSWDUSERDB_PLUGIN_ID);

        AuthMgrPlugin plugin = new AuthMgrPlugin(PASSWDUSERDB_PLUGIN_ID, PasswdUserDBAuthentication.class.getName());
        plugin.setVisible(false);
        mAuthMgrPlugins.put(PASSWDUSERDB_PLUGIN_ID, plugin);

        logger.info("AuthSubsystem: Loading auth manager plugin " + CERTUSERDB_PLUGIN_ID);

        plugin = new AuthMgrPlugin(CERTUSERDB_PLUGIN_ID, CertUserDBAuthentication.class.getName());
        plugin.setVisible(false);
        mAuthMgrPlugins.put(CERTUSERDB_PLUGIN_ID, plugin);

        // Bugscape #56659
        //   Removed NullAuthMgr to harden CMS. Otherwise,
        //   any request submitted for nullAuthMgr will
        //   be approved automatically
        //
        // logger.info("AuthSubsystem: Loading auth manager plugin " + NULL_PLUGIN_ID);
        //
        // plugin = new AuthMgrPlugin(NULL_PLUGIN_ID, NullAuthentication.class.getName());
        // plugin.setVisible(false);
        // mAuthMgrPlugins.put(NULL_PLUGIN_ID, plugin);

        logger.info("AuthSubsystem: Loading auth manager plugin " + SSLCLIENTCERT_PLUGIN_ID);

        plugin = new AuthMgrPlugin(SSLCLIENTCERT_PLUGIN_ID, SSLClientCertAuthentication.class.getName());
        plugin.setVisible(false);
        mAuthMgrPlugins.put(SSLCLIENTCERT_PLUGIN_ID, plugin);

        IConfigStore c = mConfig.getSubStore(PROP_IMPL);
        Enumeration<String> pluginIDs = c.getSubStoreNames();

        while (pluginIDs.hasMoreElements()) {
            String pluginID = pluginIDs.nextElement();
            logger.info("AuthSubsystem: Loading auth manager plugin " + pluginID);

            String pluginPath = c.getString(pluginID + "." + PROP_CLASS);
            plugin = new AuthMgrPlugin(pluginID, pluginPath);

            mAuthMgrPlugins.put(pluginID, plugin);
        }
    }

    public void loadAuthManagerInstances() throws EBaseException {

        // hardcode admin and agent auth manager instances for the server
        // to be functional

        logger.info("AuthSubsystem: Loading auth manager instance " + PASSWDUSERDB_AUTHMGR_ID);

        PasswdUserDBAuthentication passwdUserDBAuth = new PasswdUserDBAuthentication();
        passwdUserDBAuth.setAuthenticationConfig(mConfig);
        passwdUserDBAuth.init(PASSWDUSERDB_AUTHMGR_ID, PASSWDUSERDB_PLUGIN_ID, null);
        mAuthMgrInsts.put(PASSWDUSERDB_AUTHMGR_ID, new AuthManagerProxy(true, passwdUserDBAuth));

        logger.info("AuthSubsystem: Loading auth manager instance " + CERTUSERDB_AUTHMGR_ID);

        CertUserDBAuthentication certUserDBAuth = new CertUserDBAuthentication();
        certUserDBAuth.setAuthenticationConfig(mConfig);
        certUserDBAuth.init(CERTUSERDB_AUTHMGR_ID, CERTUSERDB_PLUGIN_ID, null);
        mAuthMgrInsts.put(CERTUSERDB_AUTHMGR_ID, new AuthManagerProxy(true, certUserDBAuth));

        logger.info("AuthSubsystem: Loading auth manager instance " + CMCAUTH_AUTHMGR_ID);

        CMCAuth cmcAuth = new CMCAuth();
        cmcAuth.setAuthenticationConfig(mConfig);
        cmcAuth.init(CMCAUTH_AUTHMGR_ID, CMCAUTH_PLUGIN_ID, null);
        mAuthMgrInsts.put(CMCAUTH_AUTHMGR_ID, new AuthManagerProxy(true, cmcAuth));

        // #56659
        // logger.info("AuthSubsystem: Loading auth manager instance " + NULL_AUTHMGR_ID);
        //
        // NullAuthentication nullAuth = new NullAuthentication();
        // nullAuth.setAuthenticationConfig(mConfig);
        // nullAuth.init(NULL_AUTHMGR_ID, NULL_PLUGIN_ID, null);
        // mAuthMgrInsts.put(NULL_AUTHMGR_ID, new AuthManagerProxy(true, nullAuth));

        logger.info("AuthSubsystem: Loading auth manager instance " + SSLCLIENTCERT_AUTHMGR_ID);

        SSLClientCertAuthentication sslClientCertAuth = new SSLClientCertAuthentication();
        sslClientCertAuth.setAuthenticationConfig(mConfig);
        sslClientCertAuth.init(SSLCLIENTCERT_AUTHMGR_ID, SSLCLIENTCERT_PLUGIN_ID, null);
        mAuthMgrInsts.put(SSLCLIENTCERT_AUTHMGR_ID, new AuthManagerProxy(true, sslClientCertAuth));

        AuthManagersConfig instancesConfig = mConfig.getAuthManagersConfig();
        Enumeration<String> instNames = instancesConfig.getSubStoreNames();

        while (instNames.hasMoreElements()) {
            String instName = instNames.nextElement();
            logger.info("AuthSubsystem: Loading auth manager instance " + instName);

            AuthManagerConfig authMgrConfig = instancesConfig.getAuthManagerConfig(instName);
            String implName = authMgrConfig.getString(PROP_PLUGIN);
            AuthMgrPlugin plugin = mAuthMgrPlugins.get(implName);

            if (plugin == null) {
                logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_CANT_FIND_PLUGIN", implName));
                throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implName));
            }

            String className = plugin.getClassPath();
            boolean enabled = false;
            AuthManager authMgrInst = null;

            try {
                authMgrInst = (AuthManager) Class.forName(className).getDeclaredConstructor().newInstance();
                authMgrInst.init(instName, implName, authMgrConfig);
                enabled = true;

            } catch (ClassNotFoundException e) {
                logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

            } catch (IllegalAccessException e) {
                logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

            } catch (InstantiationException e) {
                logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

            } catch (EBaseException e) {
                String message = CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", instName, e.toString());
                logger.warn("AuthSubsystem: " + message, e);
                // Skip the authentication instance if it's misconfigurated.
                // This give administrator another chance to fix the problem via console.

            } catch (Throwable e) {
                String message = CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", instName, e.toString());
                logger.warn("AuthSubsystem: " + message, e);
                // Skip the authentication instance if it's misconfigurated.
                // This give administrator another chance to fix the problem via console.
            }

            mAuthMgrInsts.put(instName, new AuthManagerProxy(enabled, authMgrInst));
        }
    }

    /**
     * Initializes the authentication subsystem from the config store.
     * Load Authentication manager plugins, create and initialize
     * initialize authentication manager instances.
     *
     * @param config The configuration store.
     */
    @Override
    public void init(IConfigStore config) throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();

        try {
            mConfig = engineConfig.getAuthenticationConfig();

            loadAuthManagerPlugins();
            loadAuthManagerInstances();

        } catch (EBaseException e) {
            logger.error("Unable to initialize AuthSubsystem: " + e.getMessage(), e);
            if (engine.isPreOpMode()) {
                logger.warn("AuthSubsystem.init(): Swallow exception in pre-op mode");
                return;
            }
            throw e;
        }
    }

    /**
     * Authenticate to the named authentication manager instance
     * <p>
     *
     * @param authCred authentication credentials subject to the
     *            requirements of each authentication manager
     * @param authMgrInstName name of the authentication manager instance
     * @return authentication token with individualized authenticated
     *         information.
     * @exception EMissingCredential If a required credential for the
     *                authentication manager is missing.
     * @exception EInvalidCredentials If the credentials cannot be authenticated
     * @exception EAuthMgrNotFound The auth manager is not found.
     * @exception EBaseException If an internal error occurred.
     */
    public IAuthToken authenticate(
            IAuthCredentials authCred, String authMgrInstName)
            throws EMissingCredential, EInvalidCredentials,
            EAuthMgrNotFound, EBaseException {
        AuthManagerProxy proxy = mAuthMgrInsts.get(authMgrInstName);

        if (proxy == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        AuthManager authMgrInst = proxy.getAuthManager();

        if (authMgrInst == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        return (authMgrInst.authenticate(authCred));
    }

    /**
     * Gets a list of required authentication credential names
     * of the specified authentication manager.
     *
     * @param authMgrInstName The authentication manager name
     * @return a Vector of required credential attribute names.
     */
    public String[] getRequiredCreds(String authMgrInstName)
            throws EAuthMgrNotFound {
        AuthManager authMgrInst = get(authMgrInstName);

        if (authMgrInst == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        return authMgrInst.getRequiredCreds();
    }

    /**
     * Gets configuration parameters for the given
     * authentication manager plugin.
     *
     * @param implName Name of the authentication plugin.
     * @return Hashtable of required parameters.
     */
    public String[] getConfigParams(String implName)
            throws EAuthMgrPluginNotFound, EBaseException {
        // is this a registered implname?
        AuthMgrPlugin plugin = mAuthMgrPlugins.get(implName);

        if (plugin == null) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_PLUGIN_NOT_FOUND", implName));
            throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implName));
        }

        // a temporary instance
        AuthManager authMgrInst = null;
        String className = plugin.getClassPath();

        try {
            authMgrInst = (AuthManager) Class.forName(className).getDeclaredConstructor().newInstance();
            return (authMgrInst.getConfigParams());

        } catch (Exception e) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);
        }
    }

    /**
     * Add an authentication manager instance.
     *
     * @param name name of the authentication manager instance
     * @param authMgrInst the authentication manager instance to be added
     */
    public void add(String name, AuthManager authMgrInst) {
        mAuthMgrInsts.put(name, new AuthManagerProxy(true, authMgrInst));
    }

    /**
     * Removes a authentication manager instance.
     * @param name name of the authentication manager
     */
    public void delete(String name) {
        mAuthMgrInsts.remove(name);
    }

    /**
     * Gets the authentication manager instance of the specified name.
     *
     * @param name name of the authentication manager instance
     * @return the named authentication manager instance
     */
    public AuthManager get(String name) {
        AuthManagerProxy proxy = mAuthMgrInsts.get(name);

        if (proxy == null)
            return null;
        return proxy.getAuthManager();
    }

    /**
     * Enumerate all authentication manager instances.
     */
    public Enumeration<AuthManager> getAuthManagers() {
        Vector<AuthManager> inst = new Vector<>();
        Enumeration<String> e = mAuthMgrInsts.keys();

        while (e.hasMoreElements()) {
            AuthManager p = get(e.nextElement());

            if (p != null) {
                inst.addElement(p);
            }
        }
        return (inst.elements());
    }

    /**
     * Enumerate all registered authentication manager plugins.
     */
    public Enumeration<AuthMgrPlugin> getAuthManagerPlugins() {
        return (mAuthMgrPlugins.elements());
    }

    /**
     * retrieve a single auth manager plugin by name
     */
    public AuthMgrPlugin getAuthManagerPluginImpl(String name) {
        return mAuthMgrPlugins.get(name);
    }

    /**
     * Retrieve a single auth manager instance
     */

    /* getconfigparams above should be recoded to use this func */
    public AuthManager getAuthManagerPlugin(String name) {
        AuthMgrPlugin plugin = mAuthMgrPlugins.get(name);
        String classpath = plugin.getClassPath();
        AuthManager authMgrInst = null;

        try {
            authMgrInst = (AuthManager) Class.forName(classpath).getDeclaredConstructor().newInstance();
            return (authMgrInst);
        } catch (Exception e) {
            logger.warn("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            return null;
        }
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the authentication subsystem
     */
    @Override
    public String getId() {
        return (mId);
    }

    /**
     * Sets id string to this subsystem.
     * <p>
     * Use with caution. Should not do it when sharing with others
     *
     * @param id name to be applied to an authentication sybsystem
     */
    @Override
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    @Override
    public void startup() throws EBaseException {
        //remove the log since it's already logged from S_ADMIN
        //String infoMsg = "Auth subsystem administration Servlet registered";
        //logger.info("AuthSubsystem: " + infoMsg);
    }

    /**
     * shuts down authentication managers one by one.
     * <P>
     */
    @Override
    public void shutdown() {
        for (AuthManagerProxy proxy : mAuthMgrInsts.values()) {

            AuthManager mgr = proxy.getAuthManager();

            logger.info("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_SHUTDOWN", mgr.getName()));

            mgr.shutdown();
        }
        mAuthMgrPlugins.clear();
        mAuthMgrInsts.clear();
    }

    /**
     * Get a hashtable containing all authentication plugins.
     *
     * @return all authentication plugins.
     */
    public Hashtable<String, AuthMgrPlugin> getPlugins() {
        return mAuthMgrPlugins;
    }

    /**
     * Get a hashtable containing all authentication instances.
     *
     * @return all authentication instances.
     */
    public Hashtable<String, AuthManagerProxy> getInstances() {
        return mAuthMgrInsts;
    }

    /**
     * Returns the root configuration storage of this system.
     *
     * @return configuration store of this subsystem
     */
    @Override
    public AuthenticationConfig getConfigStore() {
        return mConfig;
    }

    /**
     * gets the named authentication manager
     *
     * @param name of the authentication manager
     * @return the named authentication manager
     */
    public AuthManager getAuthManager(String name) {
        return get(name);
    }
}

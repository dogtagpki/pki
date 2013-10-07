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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthManagerProxy;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthMgrNotFound;
import com.netscape.certsrv.authentication.EAuthMgrPluginNotFound;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.util.Debug;

/**
 * Default authentication subsystem
 * <P>
 *
 * @author cfu
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class AuthSubsystem implements IAuthSubsystem {
    public static final String ID = "auths";

    public Hashtable<String, AuthMgrPlugin> mAuthMgrPlugins = new Hashtable<String, AuthMgrPlugin>();
    public Hashtable<String, AuthManagerProxy> mAuthMgrInsts = new Hashtable<String, AuthManagerProxy>();
    private String mId = "auths";
    private IConfigStore mConfig = null;

    private ILogger mLogger = null;

    // singleton enforcement

    private static AuthSubsystem mInstance = new AuthSubsystem();

    public static synchronized AuthSubsystem getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    private AuthSubsystem() {
    }

    /**
     * Initializes the authentication subsystem from the config store.
     * Load Authentication manager plugins, create and initialize
     * initialize authentication manager instances.
     *
     * @param owner The owner of this module.
     * @param config The configuration store.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        try {
            mLogger = CMS.getLogger();
            mConfig = config;

            // hardcode admin and agent plugins required for the server to be
            // functional.

            AuthMgrPlugin newPlugin = null;

            newPlugin = new AuthMgrPlugin(PASSWDUSERDB_PLUGIN_ID,
                    PasswdUserDBAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(PASSWDUSERDB_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(CERTUSERDB_PLUGIN_ID,
                    CertUserDBAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(CERTUSERDB_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(CHALLENGE_PLUGIN_ID,
                    ChallengePhraseAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(CHALLENGE_PLUGIN_ID, newPlugin);

            // Bugscape #56659
            //   Removed NullAuthMgr to harden CMS. Otherwise,
            //   any request submitted for nullAuthMgr will
            //   be approved automatically
            //
            // newPlugin = new AuthMgrPlugin(NULL_PLUGIN_ID,
            //            NullAuthentication.class.getName());
            // newPlugin.setVisible(false);
            // mAuthMgrPlugins.put(NULL_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(SSLCLIENTCERT_PLUGIN_ID,
                    SSLClientCertAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(SSLCLIENTCERT_PLUGIN_ID, newPlugin);

            // get auth manager plugins.

            IConfigStore c = config.getSubStore(PROP_IMPL);
            Enumeration<String> mImpls = c.getSubStoreNames();

            while (mImpls.hasMoreElements()) {
                String id = mImpls.nextElement();
                String pluginPath = c.getString(id + "." + PROP_CLASS);

                AuthMgrPlugin plugin = new AuthMgrPlugin(id, pluginPath);

                mAuthMgrPlugins.put(id, plugin);
            }
            if (Debug.ON) {
                Debug.trace("loaded auth plugins");
            }

            // hardcode admin and agent auth manager instances for the server
            // to be functional

            IAuthManager passwdUserDBAuth = new PasswdUserDBAuthentication();

            passwdUserDBAuth.init(PASSWDUSERDB_AUTHMGR_ID, PASSWDUSERDB_PLUGIN_ID, null);
            mAuthMgrInsts.put(PASSWDUSERDB_AUTHMGR_ID, new
                    AuthManagerProxy(true, passwdUserDBAuth));
            if (Debug.ON) {
                Debug.trace("loaded password based auth manager");
            }

            IAuthManager certUserDBAuth = new CertUserDBAuthentication();

            certUserDBAuth.init(CERTUSERDB_AUTHMGR_ID, CERTUSERDB_PLUGIN_ID, config);
            mAuthMgrInsts.put(CERTUSERDB_AUTHMGR_ID, new AuthManagerProxy(true, certUserDBAuth));
            if (Debug.ON) {
                Debug.trace("loaded certificate based auth manager");
            }

            IAuthManager challengeAuth = new ChallengePhraseAuthentication();

            challengeAuth.init(CHALLENGE_AUTHMGR_ID, CHALLENGE_PLUGIN_ID, config);
            mAuthMgrInsts.put(CHALLENGE_AUTHMGR_ID, new AuthManagerProxy(true, challengeAuth));
            if (Debug.ON) {
                Debug.trace("loaded challenge phrase auth manager");
            }

            IAuthManager cmcAuth = new com.netscape.cms.authentication.CMCAuth();

            cmcAuth.init(CMCAUTH_AUTHMGR_ID, CMCAUTH_PLUGIN_ID, config);
            mAuthMgrInsts.put(CMCAUTH_AUTHMGR_ID, new AuthManagerProxy(true, cmcAuth));
            if (Debug.ON) {
                Debug.trace("loaded cmc auth manager");
            }

            // #56659
            // IAuthManager nullAuth = new NullAuthentication();

            // nullAuth.init(NULL_AUTHMGR_ID, NULL_PLUGIN_ID, config);
            // mAuthMgrInsts.put(NULL_AUTHMGR_ID, new AuthManagerProxy(true, nullAuth));
            // if (Debug.ON) {
            //    Debug.trace("loaded null auth manager");
            // }

            IAuthManager sslClientCertAuth = new SSLClientCertAuthentication();

            sslClientCertAuth.init(SSLCLIENTCERT_AUTHMGR_ID, SSLCLIENTCERT_PLUGIN_ID, config);
            mAuthMgrInsts.put(SSLCLIENTCERT_AUTHMGR_ID, new AuthManagerProxy(true, sslClientCertAuth));
            if (Debug.ON) {
                Debug.trace("loaded sslClientCert auth manager");
            }

            // get auth manager instances.
            c = config.getSubStore(PROP_INSTANCE);
            Enumeration<String> instances = c.getSubStoreNames();

            while (instances.hasMoreElements()) {
                String insName = instances.nextElement();
                String implName = c.getString(insName + "." + PROP_PLUGIN);
                AuthMgrPlugin plugin =
                        mAuthMgrPlugins.get(implName);

                if (plugin == null) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_CANT_FIND_PLUGIN", implName));
                    throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND",
                            implName));
                }
                String className = plugin.getClassPath();

                boolean isEnable = false;
                // Instantiate and init the authentication manager.
                IAuthManager authMgrInst = null;

                try {
                    authMgrInst = (IAuthManager)
                            Class.forName(className).newInstance();
                    IConfigStore authMgrConfig = c.getSubStore(insName);

                    authMgrInst.init(insName, implName, authMgrConfig);
                    isEnable = true;

                    log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_AUTH_ADD_AUTH_INSTANCE", insName));
                } catch (ClassNotFoundException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
                } catch (IllegalAccessException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
                } catch (InstantiationException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", insName, e.toString()));
                    // Skip the authenticaiton instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                } catch (Throwable e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", insName, e.toString()));
                    // Skip the authenticaiton instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                }
                // add manager instance to list.
                mAuthMgrInsts.put(insName, new
                        AuthManagerProxy(isEnable, authMgrInst));
                if (Debug.ON) {
                    Debug.trace("loaded auth instance " + insName + " impl " + implName);
                }
            }
            log(ILogger.LL_INFO, CMS.getLogMessage("INIT_DONE", getId()));
        } catch (EBaseException ee) {
            if (CMS.isPreOpMode())
                return;
            throw ee;
        }
    }

    /**
     * Authenticate to the named authentication manager instance
     * <p>
     *
     * @param authCred authentication credentials subject to the
     *            requirements of each authentication manager
     * @param authMgrName name of the authentication manager instance
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
        IAuthManager authMgrInst = proxy.getAuthManager();

        if (authMgrInst == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        return (authMgrInst.authenticate(authCred));
    }

    /**
     * Gets a list of required authentication credential names
     * of the specified authentication manager.
     */
    public String[] getRequiredCreds(String authMgrInstName)
            throws EAuthMgrNotFound {
        IAuthManager authMgrInst = get(authMgrInstName);

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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_PLUGIN_NOT_FOUND", implName));
            throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implName));
        }

        // a temporary instance
        IAuthManager authMgrInst = null;
        String className = plugin.getClassPath();

        try {
            authMgrInst = (IAuthManager)
                    Class.forName(className).newInstance();
            return (authMgrInst.getConfigParams());
        } catch (InstantiationException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()));
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
        } catch (ClassNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()));
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
        } catch (IllegalAccessException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()));
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className));
        }
    }

    /**
     * Add an authentication manager instance.
     *
     * @param name name of the authentication manager instance
     * @param authMgr the authentication manager instance to be added
     */
    public void add(String name, IAuthManager authMgrInst) {
        mAuthMgrInsts.put(name, new AuthManagerProxy(true, authMgrInst));
    }

    /*
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
    public IAuthManager get(String name) {
        AuthManagerProxy proxy = mAuthMgrInsts.get(name);

        if (proxy == null)
            return null;
        return proxy.getAuthManager();
    }

    /**
     * Enumerate all authentication manager instances.
     */
    public Enumeration<IAuthManager> getAuthManagers() {
        Vector<IAuthManager> inst = new Vector<IAuthManager>();
        Enumeration<String> e = mAuthMgrInsts.keys();

        while (e.hasMoreElements()) {
            IAuthManager p = get(e.nextElement());

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
    public IAuthManager getAuthManagerPlugin(String name) {
        AuthMgrPlugin plugin = mAuthMgrPlugins.get(name);
        String classpath = plugin.getClassPath();
        IAuthManager authMgrInst = null;

        try {
            authMgrInst = (IAuthManager) Class.forName(classpath).newInstance();
            return (authMgrInst);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()));
            return null;
        }
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the authentication subsystem
     */
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
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    public void startup() throws EBaseException {
        //remove the log since it's already logged from S_ADMIN
        //String infoMsg = "Auth subsystem administration Servlet registered";
        //log(ILogger.LL_INFO, infoMsg);
    }

    /**
     * shuts down authentication managers one by one.
     * <P>
     */
    public void shutdown() {
        for (AuthManagerProxy proxy : mAuthMgrInsts.values()) {

            IAuthManager mgr = proxy.getAuthManager();

            log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_SHUTDOWN", mgr.getName()));

            mgr.shutdown();
        }
        mAuthMgrPlugins.clear();
        mAuthMgrInsts.clear();
    }

    public Hashtable<String, AuthMgrPlugin> getPlugins() {
        return mAuthMgrPlugins;
    }

    public Hashtable<String, AuthManagerProxy> getInstances() {
        return mAuthMgrInsts;
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * gets the named authentication manager
     *
     * @param name of the authentication manager
     * @return the named authentication manager
     */
    public IAuthManager getAuthManager(String name) {
        return get(name);
    }

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
                level, msg);
    }

}

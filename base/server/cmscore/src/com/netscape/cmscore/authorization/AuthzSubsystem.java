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
package com.netscape.cmscore.authorization;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzManagerProxy;
import com.netscape.certsrv.authorization.AuthzMgrPlugin;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.authorization.EAuthzMgrNotFound;
import com.netscape.certsrv.authorization.EAuthzMgrPluginNotFound;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.util.Debug;

/**
 * Default authorization subsystem
 * <P>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class AuthzSubsystem implements IAuthzSubsystem {
    public static final String ID = "authz";

    public Hashtable<String, AuthzMgrPlugin> mAuthzMgrPlugins = new Hashtable<String, AuthzMgrPlugin>();
    public Hashtable<String, AuthzManagerProxy> mAuthzMgrInsts = new Hashtable<String, AuthzManagerProxy>();
    private String mId = "authz";
    private IConfigStore mConfig = null;

    private ILogger mLogger = null;

    // singleton enforcement

    private static AuthzSubsystem mInstance = new AuthzSubsystem();

    public static synchronized AuthzSubsystem getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    private AuthzSubsystem() {
    }

    /**
     * Initializes the authorization subsystem from the config store.
     * Load Authorization manager plugins, create and initialize
     * initialize authorization manager instances.
     *
     * @param owner The owner of this module.
     * @param config The configuration store.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        try {
            mLogger = CMS.getLogger();
            mConfig = config;

            // get authz manager plugins.

            IConfigStore c = config.getSubStore(PROP_IMPL);
            Enumeration<String> mImpls = c.getSubStoreNames();

            while (mImpls.hasMoreElements()) {
                String id = mImpls.nextElement();
                String pluginPath = c.getString(id + "." + PROP_CLASS);

                AuthzMgrPlugin plugin = new AuthzMgrPlugin(id, pluginPath);

                mAuthzMgrPlugins.put(id, plugin);
            }
            if (Debug.ON) {
                Debug.trace("loaded authz plugins");
            }

            // get authz manager instances.

            c = config.getSubStore(PROP_INSTANCE);
            Enumeration<String> instances = c.getSubStoreNames();

            while (instances.hasMoreElements()) {
                String insName = instances.nextElement();
                String implName = c.getString(insName + "." + PROP_PLUGIN);
                AuthzMgrPlugin plugin =
                        mAuthzMgrPlugins.get(implName);

                if (plugin == null) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_FOUND", implName));
                    throw new EAuthzMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_PLUGIN_NOT_FOUND",
                            implName));
                } else {
                    CMS.debug(
                            CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_FOUND", implName));
                }

                String className = plugin.getClassPath();

                boolean isEnable = false;
                // Instantiate and init the authorization manager.
                IAuthzManager authzMgrInst = null;

                try {
                    authzMgrInst = (IAuthzManager)
                            Class.forName(className).newInstance();
                    IConfigStore authzMgrConfig = c.getSubStore(insName);

                    authzMgrInst.init(insName, implName, authzMgrConfig);
                    isEnable = true;

                    log(ILogger.LL_INFO,
                            CMS.getLogMessage("CMSCORE_AUTHZ_INSTANCE_ADDED", insName));
                } catch (ClassNotFoundException e) {
                    String errMsg = "AuthzSubsystem:: init()-" + e.toString();

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", errMsg));
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
                } catch (IllegalAccessException e) {
                    String errMsg = "AuthzSubsystem:: init()-" + e.toString();

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", errMsg));
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
                } catch (InstantiationException e) {
                    String errMsg = "AuthzSubsystem: init()-" + e.toString();

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", errMsg));
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_INIT_FAILED", insName, e.toString()));
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                } catch (Throwable e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_INIT_FAILED", insName, e.toString()));
                    // Skip the authorization instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                }
                // add manager instance to list.
                mAuthzMgrInsts.put(insName, new
                        AuthzManagerProxy(isEnable, authzMgrInst));
                if (Debug.ON) {
                    Debug.trace("loaded authz instance " + insName + " impl " + implName);
                }
            }
        } catch (EBaseException ee) {
            if (CMS.isPreOpMode())
                return;
            throw ee;
        }

        log(ILogger.LL_INFO, CMS.getLogMessage("INIT_DONE", getId()));
    }

    /**
     * authMgrzAccessInit is for servlets who want to initialize their
     * own authorization information before full operation. It is supposed
     * to be called during the init() method of a servlet.
     *
     * @param authzMgrName The authorization manager name
     * @param accessInfo the access information to be initialized. currently it's acl string in the format specified in
     *            the authorization manager
     */
    public void authzMgrAccessInit(String authzMgrInstName, String accessInfo)
            throws EAuthzMgrNotFound, EBaseException {
        AuthzManagerProxy proxy = mAuthzMgrInsts.get(authzMgrInstName);

        if (proxy == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        IAuthzManager authzMgrInst = proxy.getAuthzManager();

        if (authzMgrInst == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }

        authzMgrInst.accessInit(accessInfo);
    }

    /**
     * Authorization to the named authorization manager instance
     *
     * @param authzMgrName The authorization manager name
     * @param authToken the authenticaton token associated with a user
     * @param resource the resource protected by the authorization system
     * @param operation the operation for resource protected by the authoriz
     *            n system
     * @exception EBaseException If an error occurs during authorization.
     * @return a authorization token.
     */
    public AuthzToken authorize(
            String authzMgrInstName, IAuthToken authToken,
            String resource, String operation)
            throws EAuthzMgrNotFound, EBaseException {

        AuthzManagerProxy proxy = mAuthzMgrInsts.get(authzMgrInstName);

        if (proxy == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        IAuthzManager authzMgrInst = proxy.getAuthzManager();

        if (authzMgrInst == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        return (authzMgrInst.authorize(authToken, resource, operation));
    }

    public AuthzToken authorize(
            String authzMgrInstName, IAuthToken authToken, String exp)
            throws EAuthzMgrNotFound, EBaseException {

        AuthzManagerProxy proxy = mAuthzMgrInsts.get(authzMgrInstName);

        if (proxy == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        IAuthzManager authzMgrInst = proxy.getAuthzManager();

        if (authzMgrInst == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        return (authzMgrInst.authorize(authToken, exp));
    }

    /**
     * Gets configuration parameters for the given
     * authorization manager plugin.
     *
     * @param implName Name of the authorization plugin.
     * @return Hashtable of required parameters.
     */
    public String[] getConfigParams(String implName)
            throws EAuthzMgrPluginNotFound, EBaseException {
        // is this a registered implname?
        AuthzMgrPlugin plugin = mAuthzMgrPlugins.get(implName);

        if (plugin == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_FOUND", implName));
            throw new EAuthzMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_PLUGIN_NOT_FOUND",
                    implName));
        }

        // a temporary instance
        IAuthzManager authzMgrInst = null;
        String className = plugin.getClassPath();

        try {
            authzMgrInst = (IAuthzManager)
                    Class.forName(className).newInstance();
            return (authzMgrInst.getConfigParams());
        } catch (InstantiationException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()));
            throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
        } catch (ClassNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()));
            throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
        } catch (IllegalAccessException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()));
            throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
        }
    }

    /**
     * Add an authorization manager instance.
     *
     * @param name name of the authorization manager instance
     * @param authzMgr the authorization manager instance to be added
     */
    public void add(String name, IAuthzManager authzMgrInst) {
        mAuthzMgrInsts.put(name, new AuthzManagerProxy(true, authzMgrInst));
    }

    /*
     * Removes a authorization manager instance.
     * @param name name of the authorization manager
     */
    public void delete(String name) {
        mAuthzMgrInsts.remove(name);
    }

    /**
     * Gets the authorization manager instance of the specified name.
     *
     * @param name name of the authorization manager instance
     * @return the named authorization manager instance
     */
    public IAuthzManager get(String name) {
        AuthzManagerProxy proxy = mAuthzMgrInsts.get(name);

        if (proxy == null)
            return null;
        return proxy.getAuthzManager();
    }

    /**
     * Enumerate all authorization manager instances.
     */
    public Enumeration<IAuthzManager> getAuthzManagers() {
        Vector<IAuthzManager> inst = new Vector<IAuthzManager>();
        Enumeration<String> e = mAuthzMgrInsts.keys();

        while (e.hasMoreElements()) {
            IAuthzManager p = get(e.nextElement());

            if (p != null) {
                inst.addElement(p);
            }
        }
        return (inst.elements());
    }

    /**
     * Enumerate all registered authorization manager plugins.
     */
    public Enumeration<AuthzMgrPlugin> getAuthzManagerPlugins() {
        return (mAuthzMgrPlugins.elements());
    }

    /**
     * retrieve a single authz manager plugin by name
     */
    public AuthzMgrPlugin getAuthzManagerPluginImpl(String name) {
        return mAuthzMgrPlugins.get(name);
    }

    /**
     * Retrieve a single authz manager instance
     */

    /* getconfigparams above should be recoded to use this func */
    public IAuthzManager getAuthzManagerPlugin(String name) {
        AuthzMgrPlugin plugin = mAuthzMgrPlugins.get(name);
        String classpath = plugin.getClassPath();
        IAuthzManager authzMgrInst = null;

        try {
            authzMgrInst = (IAuthzManager) Class.forName(classpath).newInstance();
            return (authzMgrInst);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()));
            return null;
        }
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the authorization subsystem
     */
    public String getId() {
        return (mId);
    }

    /**
     * Sets id string to this subsystem.
     * <p>
     * Use with caution. Should not do it when sharing with others
     *
     * @param id name to be applied to an authorization sybsystem
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    public void startup() throws EBaseException {
        //remove the log since it's already logged from S_ADMIN
        //String infoMsg = "Authz subsystem administration Servlet registered";
        //log(ILogger.LL_INFO, infoMsg);
    }

    /**
     * shuts down authorization managers one by one.
     * <P>
     */
    public void shutdown() {
        for (AuthzManagerProxy proxy : mAuthzMgrInsts.values()) {
            IAuthzManager mgr = proxy.getAuthzManager();

            //String infoMsg =
            //        "Shutting down authz manager instance " + mgr.getName();
            //log(ILogger.LL_INFO, infoMsg);
            if (mgr != null)
                mgr.shutdown();
        }
        mAuthzMgrPlugins.clear();
        mAuthzMgrInsts.clear();
    }

    public Hashtable<String, AuthzMgrPlugin> getPlugins() {
        return mAuthzMgrPlugins;
    }

    public Hashtable<String, AuthzManagerProxy> getInstances() {
        return mAuthzMgrInsts;
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
     * gets the named authorization manager
     *
     * @param name of the authorization manager
     * @return the named authorization manager
     */
    public IAuthzManager getAuthzManager(String name) {
        return get(name);
    }

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHORIZATION,
                level, msg);
    }

}

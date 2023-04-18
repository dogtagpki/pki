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

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthorizationConfig;
import org.dogtagpki.server.authorization.AuthzManager;
import org.dogtagpki.server.authorization.AuthzManagerConfig;
import org.dogtagpki.server.authorization.AuthzManagerProxy;
import org.dogtagpki.server.authorization.AuthzManagersConfig;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.authorization.AuthzMgrPlugin;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.authorization.EAuthzMgrNotFound;
import com.netscape.certsrv.authorization.EAuthzMgrPluginNotFound;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;

/**
 * Default authorization subsystem
 * <P>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class AuthzSubsystem extends Subsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthzSubsystem.class);

    public final static String ID = "authz";

    public final static String PROP_CLASS = "class";
    public final static String PROP_IMPL = "impl";

    public Hashtable<String, AuthzMgrPlugin> mAuthzMgrPlugins = new Hashtable<>();
    public Hashtable<String, AuthzManagerProxy> mAuthzMgrInsts = new Hashtable<>();
    private String mId = "authz";
    private AuthorizationConfig mConfig;

    /**
     * Initializes the authorization subsystem from the config store.
     * Load Authorization manager plugins, create and initialize
     * initialize authorization manager instances.
     *
     * @param config Subsystem configuration
     * @exception Exception Unable to initialize subsystem
     */
    @Override
    public void init(ConfigStore config) throws Exception {

        EngineConfig engineConfig = engine.getConfig();

        try {
            mConfig = engineConfig.getAuthorizationConfig();

            // get authz manager plugins.

            ConfigStore c = mConfig.getSubStore(PROP_IMPL, ConfigStore.class);
            Enumeration<String> mImpls = c.getSubStoreNames().elements();

            while (mImpls.hasMoreElements()) {
                String id = mImpls.nextElement();
                String pluginPath = c.getString(id + "." + PROP_CLASS);

                AuthzMgrPlugin plugin = new AuthzMgrPlugin(id, pluginPath);

                mAuthzMgrPlugins.put(id, plugin);
            }

            logger.debug("loaded authz plugins");

            // get authz manager instances.

            AuthzManagersConfig instancesConfig = mConfig.getAuthzManagersConfig();
            Enumeration<String> instances = instancesConfig.getSubStoreNames().elements();

            while (instances.hasMoreElements()) {
                String insName = instances.nextElement();

                AuthzManagerConfig authzMgrConfig = instancesConfig.getAuthzManagerConfig(insName);
                String implName = authzMgrConfig.getPluginName();
                AuthzMgrPlugin plugin =
                        mAuthzMgrPlugins.get(implName);

                if (plugin == null) {
                    logger.error("AuthzSubsystem: " + CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_FOUND", implName));
                    throw new EAuthzMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_PLUGIN_NOT_FOUND",
                            implName));
                }
                logger.debug(CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_FOUND", implName));

                String className = plugin.getClassPath();

                boolean isEnable = false;
                // Instantiate and init the authorization manager.
                AuthzManager authzMgrInst = null;

                try {
                    authzMgrInst = (AuthzManager) Class.forName(className).getDeclaredConstructor().newInstance();
                    authzMgrInst.setCMSEngine(engine);
                    authzMgrInst.init(insName, implName, authzMgrConfig);
                    isEnable = true;

                    logger.info("AuthzSubsystem: " + CMS.getLogMessage("CMSCORE_AUTHZ_INSTANCE_ADDED", insName));

                } catch (ClassNotFoundException e) {
                    logger.error("AuthzSubsystem: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()), e);
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));

                } catch (IllegalAccessException e) {
                    logger.error("AuthzSubsystem: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()), e);
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));

                } catch (InstantiationException e) {
                    logger.error("AuthzSubsystem: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()), e);
                    throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));

                } catch (Exception e) {
                    // Skip the authorization instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                    logger.warn("AuthzSubsystem: unable to initialize authz instance: " + insName + ": " + e.getMessage(), e);
                }

                // add manager instance to list.
                mAuthzMgrInsts.put(insName, new
                        AuthzManagerProxy(isEnable, authzMgrInst));

                logger.debug("loaded authz instance " + insName + " impl " + implName);
            }

        } catch (EBaseException e) {
            logger.error("Unable to initialize AuthzSubsystem: " + e.getMessage(), e);
            if (engine.isPreOpMode()) {
                logger.warn("AuthzSubsystem.init(): Swallow exception in pre-op mode");
                return;
            }
            throw e;
        }

        logger.info("AuthzSubsystem: " + CMS.getLogMessage("INIT_DONE", getId()));
    }

    /**
     * authMgrzAccessInit is for servlets who want to initialize their
     * own authorization information before full operation. It is supposed
     * to be called during the init() method of a servlet.
     *
     * @param authzMgrInstName The authorization manager name
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
        AuthzManager authzMgrInst = proxy.getAuthzManager();

        if (authzMgrInst == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }

        authzMgrInst.accessInit(accessInfo);
    }

    public void addACLInfo(String aclMethod, String aclInfo) throws EBaseException {

        StringTokenizer tokenizer = new StringTokenizer(aclInfo, "#");

        while (tokenizer.hasMoreTokens()) {
            String acl = tokenizer.nextToken();
            authzMgrAccessInit(aclMethod, acl);
        }
    }

    /**
     * Authorization to the named authorization manager instance
     *
     * @param authzMgrInstName The authorization manager name
     * @param authToken the authentication token associated with a user
     * @param resource the resource protected by the authorization system
     * @param operation the operation for resource protected by the authoriz
     *            n system
     * @exception EBaseException If an error occurs during authorization.
     * @return a authorization token.
     */
    public AuthzToken authorize(
            String authzMgrInstName, AuthToken authToken,
            String resource, String operation, String realm)
            throws EAuthzMgrNotFound, EBaseException {

        AuthzManagerProxy proxy = mAuthzMgrInsts.get(authzMgrInstName);

        if (proxy == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        AuthzManager authzMgrInst = proxy.getAuthzManager();

        if (authzMgrInst == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }

        if ((realm != null) && (resource != null)) {
            resource = realm + "." + resource;
        }
        return (authzMgrInst.authorize(authToken, resource, operation));
    }

    public AuthzToken authorize(String authzMgrName, AuthToken authToken, String resource, String operation)
            throws EBaseException {
        return authorize(authzMgrName, authToken, resource, operation, null);
    }

    public AuthzToken authorize(
            String authzMgrInstName, AuthToken authToken, String exp)
            throws EAuthzMgrNotFound, EBaseException {

        AuthzManagerProxy proxy = mAuthzMgrInsts.get(authzMgrInstName);

        if (proxy == null) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthzMgrNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_NOT_FOUND", authzMgrInstName));
        }
        AuthzManager authzMgrInst = proxy.getAuthzManager();

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
            logger.error("AuthzSubsystem: " + CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_FOUND", implName));
            throw new EAuthzMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZMGR_PLUGIN_NOT_FOUND",
                    implName));
        }

        // a temporary instance
        AuthzManager authzMgrInst = null;
        String className = plugin.getClassPath();

        try {
            authzMgrInst = (AuthzManager) Class.forName(className).getDeclaredConstructor().newInstance();
            return (authzMgrInst.getConfigParams());
        } catch (Exception e) {
            logger.error("AuthzSubsystem: " + CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()), e);
            throw new EAuthzException(CMS.getUserMessage("CMS_AUTHORIZATION_LOAD_CLASS_FAIL", className));
        }
    }

    /**
     * Add an authorization manager instance.
     *
     * @param name name of the authorization manager instance
     * @param authzMgrInst the authorization manager instance to be added
     */
    public void add(String name, AuthzManager authzMgrInst) {
        mAuthzMgrInsts.put(name, new AuthzManagerProxy(true, authzMgrInst));
    }

    /**
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
    public AuthzManager get(String name) {
        AuthzManagerProxy proxy = mAuthzMgrInsts.get(name);

        if (proxy == null)
            return null;
        return proxy.getAuthzManager();
    }

    /**
     * Enumerate all authorization manager instances.
     */
    public Enumeration<AuthzManager> getAuthzManagers() {
        Vector<AuthzManager> inst = new Vector<>();
        Enumeration<String> e = mAuthzMgrInsts.keys();

        while (e.hasMoreElements()) {
            AuthzManager p = get(e.nextElement());

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
    public AuthzManager getAuthzManagerPlugin(String name) {
        AuthzMgrPlugin plugin = mAuthzMgrPlugins.get(name);
        String classpath = plugin.getClassPath();
        AuthzManager authzMgrInst = null;

        try {
            authzMgrInst = (AuthzManager) Class.forName(classpath).getDeclaredConstructor().newInstance();
            return (authzMgrInst);
        } catch (Exception e) {
            logger.warn("AuthzSubsystem: " + CMS.getLogMessage("CMSCORE_AUTHZ_PLUGIN_NOT_CREATED", e.toString()), e);
            return null;
        }
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the authorization subsystem
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
     * @param id name to be applied to an authorization sybsystem
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
        //String infoMsg = "Authz subsystem administration Servlet registered";
        //logger.info("AuthzSubsystem: " + infoMsg);
    }

    /**
     * shuts down authorization managers one by one.
     * <P>
     */
    @Override
    public void shutdown() {
        for (AuthzManagerProxy proxy : mAuthzMgrInsts.values()) {
            AuthzManager mgr = proxy.getAuthzManager();

            //String infoMsg =
            //        "Shutting down authz manager instance " + mgr.getName();
            //logger.info("AuthzSubsystem: " + infoMsg);
            if (mgr != null)
                mgr.shutdown();
        }
        mAuthzMgrPlugins.clear();
        mAuthzMgrInsts.clear();
    }

    /**
     * Get a hashtable containing all authentication plugins.
     *
     * @return all authentication plugins.
     */
    public Hashtable<String, AuthzMgrPlugin> getPlugins() {
        return mAuthzMgrPlugins;
    }

    /**
     * Get a hashtable containing all authentication instances.
     *
     * @return all authentication instances.
     */
    public Hashtable<String, AuthzManagerProxy> getInstances() {
        return mAuthzMgrInsts;
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * gets the named authorization manager
     *
     * @param name of the authorization manager
     * @return the named authorization manager
     */
    public AuthzManager getAuthzManager(String name) {
        return get(name);
    }

    /**
     * Authorize the user against the specified realm.  Looks for authz manager
     * associated with the plugin and authenticates if present.
     *
     * @param realm
     * @param authToken
     * @param owner TODO
     * @param resource
     * @param operation
     * @throws EBaseException if any error occurs during authentication.
     */
    public void checkRealm(String realm, AuthToken authToken, String owner, String resource, String operation)
            throws EBaseException {
        // if no realm entry, SUCCESS by default
        if (realm == null) return;

        // if record owner == requester, SUCCESS
        if ((owner != null) && owner.equals(authToken.getInString(AuthToken.USER_ID))) return;

        String mgrName = getAuthzManagerNameByRealm(realm);

        AuthzToken authzToken = authorize(mgrName, authToken, resource, operation, realm);
        if (authzToken == null) {
            throw new EAuthzAccessDenied("Not authorized by ACL realm");
        }
    }

    /**
     * Given a realm name, return the name of an authz manager for that realm.
     *
     * @throws EAuthzUnknownRealm if no authz manager is found.
     */
    public String getAuthzManagerNameByRealm(String realm) throws EAuthzUnknownRealm {
        for (AuthzManagerProxy proxy : mAuthzMgrInsts.values()) {
            AuthzManager mgr = proxy.getAuthzManager();
            if (mgr != null) {
                AuthzManagerConfig cfg = mgr.getConfigStore();
                String mgrRealmString = null;
                try {
                    mgrRealmString = cfg.getRealmName();
                } catch (EBaseException e) {
                    // never mind
                }
                if (mgrRealmString == null) continue;

                List<String> mgrRealms = Arrays.asList(mgrRealmString.split(","));
                for (String mgrRealm : mgrRealms) {
                    if (mgrRealm.equals(realm))
                        return mgr.getName();
                }
            }
        }

        throw new EAuthzUnknownRealm("Realm not found");
    }
}

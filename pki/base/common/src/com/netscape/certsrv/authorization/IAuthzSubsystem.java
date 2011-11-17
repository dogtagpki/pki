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
package com.netscape.certsrv.authorization;

import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;

/**
 * An interface that represents an authorization component
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IAuthzSubsystem extends ISubsystem {
    
    /**
     * Constant for auths.
     */
    public static final String ID = "authz";

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

    /**
     * authorize the user associated with the given authToken for a given
     * operation with the given authorization manager name
     * @param authzMgrName The authorization manager name
     * @param authToken the authenticaton token associated with a user
     * @param resource the resource protected by the authorization system
     * @param operation the operation for resource protected by the authorization system
     * @return a authorization token.
     * @exception EBaseException If an error occurs during authorization.
     */
    public AuthzToken authorize(String authzMgrName, IAuthToken authToken,
        String resource, String operation)
        throws EBaseException;

    public AuthzToken authorize(String authzMgrName, IAuthToken authToken,
        String exp) throws EBaseException;

    /**
     * Adds (registers) the given authorization manager.
     * @param name The authorization manager name
     * @param authzMgr The authorization manager instance.
     */
    public void add(String name, IAuthzManager authzMgr);

    /**
     * Deletes (deregisters) the given authorization manager.
     * @param name The authorization manager name to delete.
     */
    public void delete(String name);

    /**
     * Gets the Authorization manager instance of the specified name.
     * @param name The authorization manager's name.
     * @return an authorization manager interface
     */
    public IAuthzManager getAuthzManager(String name) throws EBaseException;

    /**
     * Gets an enumeration of authorization managers registered to the
     * authorization component.
     * @return a list of authorization managers
     */
    public Enumeration<IAuthzManager> getAuthzManagers();

    /**
     * Initialize authz info - usually used for BasicAclAuthz
     * 
     * @param authzMgrName name of the authorization manager
     * @param accessInfo string representation of the ACL
     * @exception EBaseException if authorization manager is not found
     */
    public void authzMgrAccessInit(String authzMgrName, String accessInfo) throws EBaseException;

    /**
     * Gets an enumeration of authorization manager plugins.
     * @return list of authorization manager plugins
     */
    public Enumeration<AuthzMgrPlugin>  getAuthzManagerPlugins();

    /**
     * Gets a single authorization manager plugin implementation
     * @param name given authorization plugin name
     * @return authorization manager plugin
     */
    public IAuthzManager getAuthzManagerPlugin(String name);

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
    public Hashtable<String, AuthzMgrPlugin> getPlugins();

    /**
     * Get a hashtable containing all authentication instances.
     * @return all authentication instances.
     */
    public Hashtable<String, AuthzManagerProxy> getInstances();

    /**
     * Get an authorization manager interface for the given name.
     * @param name given authorization manager name.
     * @return an authorization manager interface
     */
    public IAuthzManager get(String name);
}


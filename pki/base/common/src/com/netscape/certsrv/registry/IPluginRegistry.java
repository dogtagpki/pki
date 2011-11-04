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
package com.netscape.certsrv.registry;


import java.util.Enumeration;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;


/**
 * This represents the registry subsystem that manages 
 * mulitple types of plugin information.
 *
 * The plugin information includes id, name, 
 * classname, and description.
 *
 * @version $Revision$, $Date$
 */
public interface IPluginRegistry extends ISubsystem {

    public static final String ID = "registry";

    /**
     * Returns handle to the registry configuration file.
     *
     * @return configuration store of registry subsystem
     */
    public IConfigStore getFileConfigStore();

    /**
     * Returns all type names.
     *
     * @return a list of String-based names
     */
    public Enumeration getTypeNames();

    /**
     * Returns a list of plugin identifiers of the given type.
     *
     * @param type plugin type
     * @return a list of plugin IDs
     */
    public Enumeration getIds(String type);

    /**
     * Retrieves the plugin information.
     *
     * @param type plugin type
     * @param id plugin id
     * @return plugin info
     */
    public IPluginInfo getPluginInfo(String type, String id);

    /**
     * Adds plugin info.
     *
     * @param type plugin type
     * @param id plugin id
     * @param info plugin info
     * @exception ERegistryException failed to add plugin
     */
    public void addPluginInfo(String type, String id, IPluginInfo info)
        throws ERegistryException;

    /**
     * Removes plugin info.
     */
    public void removePluginInfo(String type, String id)
     throws ERegistryException;

    /**
     * Creates a pluginInfo
     */
    public IPluginInfo createPluginInfo(String name, String desc, 
       String classPath);
}

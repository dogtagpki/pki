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
package com.netscape.certsrv.base;


import java.util.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;

/**
 * This interface represents a plugin instance.
 *
 * @version $Revision$, $Date$
 */
public interface IPluginImpl {

    public static final String PROP_IMPLNAME = "implName";

    /**
     * Gets the description for this plugin instance.
     * <P>
     * @return The Description for this plugin instance.
     */
    public String getDescription();

    /**
     * Returns the name of the plugin class.
     * <P>
     *
     * @return The name of the plugin class.
     */
    public String getImplName();

    /**
     * Returns the name of the plugin instance.
     * <P>
     *
     * @return The name of the plugin instance. If none	is set 
     * the name of the implementation will be returned.xxxx
     */
    public String getInstanceName();

    /**
     * Initializes this plugin instance.
     *
     * @param sys parent subsystem
     * @param instanceName instance name of this plugin
     * @param className class name of this plugin
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem sys, String instanceName, String className, 
        IConfigStore config)
        throws EBaseException;

    /**
     * Shutdowns this plugin.
     */
    public void shutdown();

    /**
     * Retrieves the configuration store.
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore();

    /**
     * Return configured parameters for a plugin instance.
     *
     * @return nvPairs A Vector of name/value pairs. Each name/value 
     *      pair is constructed as a String in name=value format.
     */
    public Vector getInstanceParams();

    /**
     * Retrieves a list of configuration parameter names.
     *
     * @return a list of parameter names
     */
    public String[] getConfigParams();

    /**
     * Return default parameters for a plugin implementation.
     *
     * @return nvPairs A Vector of name/value pairs. Each name/value
     *		  		pair is constructed as a String in name=value.
     */
    public Vector getDefaultParams();

}


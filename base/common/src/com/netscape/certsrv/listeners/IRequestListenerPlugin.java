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
package com.netscape.certsrv.listeners;


import com.netscape.certsrv.base.*;

/**
 * This interface represents a plug-in listener. Implement this class to
 * add the listener to an ARequestNotifier of a subsystem.
 * <P>
 * @version $Revision$, $Date$
 */
public interface IRequestListenerPlugin {
    
    /**
     * get the registered class name set in the init() method.
     * <P>
     *  @return the Name.
     */
    public String getName();
    
    /**
     * get the plugin implementaion name set in the init() method.
     * <P>
     * @return the plugin implementation name.
     */
    public String getImplName();
    
    /**
     * the subsystem call this method to initialize the plug-in.
     * <P>
     * @param name the registered class name of the plug-in.
     * @param implName the implemetnation name of the plug-in.
     * @param config the configuration store where the.
     * properties of the plug-in are stored.
     * @exception EBaseException throws base exception in the certificate server.
     */
    public void   init(String name, String implName, IConfigStore config)
    throws EBaseException;
    /**
     * shutdown the plugin.
     */
    public void shutdown();
    /**
     * get the configuration parameters of the plug-in.
     * <P>
     * @return the configuration parameters.
     * @exception EBaseException throws base exception in the certificate server.
     */
    public String[] getConfigParams()
    throws EBaseException;
    /**
     * get the configuration store of the plugin where the
     * configuration parameters of the plug-in are stored.
     * <P>
     * @return the configuration store.
     */
    
    public IConfigStore getConfigStore();
    
}

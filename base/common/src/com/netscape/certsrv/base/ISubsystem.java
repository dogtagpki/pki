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

/**
 * An interface represents a CMS subsystem. CMS is made up of a list
 * subsystems. Each subsystem is responsible for a set of
 * speciailized functions.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface ISubsystem {

    /**
     * Retrieves the name of this subsystem.
     * 
     * @return subsystem identifier
     */
    public String getId();

    /**
     * Sets specific to this subsystem.
     * 
     * @param id subsystem identifier
     * @exception EBaseException failed to set id
     */
    public void setId(String id) throws EBaseException;

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     * 
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException;

    /**
     * Notifies this subsystem if owner is in running mode.
     * 
     * @exception EBaseException failed to start up
     */
    public void startup() throws EBaseException;

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown();

    /**
     * Returns the root configuration storage of this system.
     * <P>
     * 
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore();
}

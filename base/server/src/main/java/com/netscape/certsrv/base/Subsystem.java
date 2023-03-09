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

import com.netscape.cmscore.base.ConfigStore;

/**
 * This class represents a basic subsystem. Each basic
 * subsystem is named with an identifier and has a
 * configuration store.
 */
public abstract class Subsystem {

    protected ConfigStore config;
    protected String id;

    /**
     * Initializes this subsystem with the given configuration store.
     *
     * @param config Subsystem configuration
     * @exception Exception Unable to initialize subsystem
     */
    public void init(ConfigStore config) throws Exception {
        this.config = config;
    }

    /**
     * Returns the configuration store.
     *
     * @return configuration store
     */
    public ConfigStore getConfigStore() {
        return config;
    }

    /**
     * Sets the identifier of this subsystem.
     *
     * @param id subsystem identifier
     * @exception EBaseException failed to set id
     */
    public void setId(String id) throws EBaseException {
        this.id = id;
    }

    /**
     * Retrieves the subsystem identifier.
     *
     * @return subsystem identifier
     */
    public String getId() {
        return id;
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     *
     * @exception EBaseException failed to start up
     */
    public void startup() throws EBaseException {
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     */
    public void shutdown() {
    }
}

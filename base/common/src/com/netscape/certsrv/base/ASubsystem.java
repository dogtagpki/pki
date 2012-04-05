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
 * This class represents a basic subsystem. Each basic
 * subsystem is named with an identifier and has a
 * configuration store.
 *
 * @version $Revision$, $Date$
 */
public abstract class ASubsystem implements ISubsystem {

    private ISubsystem mParent;
    private IConfigStore mCfg;
    private String mId;

    /**
     * Initializes this subsystem.
     *
     * @param parent parent subsystem
     * @param cfg configuration store
     */
    public void init(ISubsystem parent, IConfigStore cfg) {
        mParent = parent;
        mCfg = cfg;
    }

    /**
     * Retrieves the configuration store.
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mCfg;
    }

    /**
     * Sets the identifier of this subsystem.
     *
     * @param id subsystem identifier
     */
    public void setId(String id) {
        mId = id;
    }

    /**
     * Retrieves the subsystem identifier.
     *
     * @return subsystem identifier
     */
    public String getId() {
        return mId;
    }
}

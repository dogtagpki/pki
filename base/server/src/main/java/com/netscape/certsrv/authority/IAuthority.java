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
package com.netscape.certsrv.authority;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStore;

/**
 * Authority interface.
 *
 * @version $Revision$ $Date$
 */
public interface IAuthority {

    /**
     * Retrieves the name of this authority.
     *
     * @return authority identifier
     */
    public String getId();

    /**
     * Sets specific to this authority.
     *
     * @param id authority identifier
     * @exception EBaseException failed to set id
     */
    public void setId(String id) throws EBaseException;

    /**
     * Initializes this authority with the given configuration store.
     *
     * @param config configuration store
     * @exception Exception failed to initialize
     */
    public void init(ConfigStore config) throws Exception;

    /**
     * Notifies this authority if owner is in running mode.
     *
     * @exception EBaseException failed to start up
     */
    public void startup() throws EBaseException;

    /**
     * Stops this authority. The owner may call shutdown
     * anytime after initialization.
     */
    public void shutdown();

    /**
     * Returns the configuration storage of this authority.
     *
     * @return configuration store of this authority
     */
    public ConfigStore getConfigStore();

    /**
     * nickname of signing (id) cert
     */
    public String getNickname();

    /**
     * return official product name.
     */
    public String getOfficialName();

}

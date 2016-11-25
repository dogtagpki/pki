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
package com.netscape.cms.authorization;

// cert server imports.
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class for basic acls authorization manager
 *
 * @version $Revision$, $Date$
 */
public class BasicAclAuthz extends AAclAuthz
        implements IAuthzManager, IExtendedPluginInfo {

    static {
        mExtendedPluginInfo.add("nothing for now");
    }

    /**
     * Default constructor
     */
    public BasicAclAuthz() {

        /* Holds configuration parameters accepted by this implementation.
         * This list is passed to the configuration console so configuration
         * for instances of this implementation can be configured through the
         * console.
         */
        mConfigParams =
                new String[] {
                    "dummy"
                };
    }

    /**
     *
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        super.init(name, implName, config);

        log(ILogger.LL_INFO, "initialization done");
    }

    /**
     * graceful shutdown
     */
    public void shutdown() {
        log(ILogger.LL_INFO, "shutting down");
    }
}

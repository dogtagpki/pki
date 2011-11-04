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
package com.netscape.certsrv.publish;


import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;


/** 
 * Interface for publishing rule which associates a Publisher with a Mapper.
 *
 * @version $Revision$ $Date$
 */
public interface ILdapRule extends ILdapPlugin {
    public static final String PROP_PREDICATE = "predicate";
    public static final String PROP_ENABLE = "enable";
    public static final String PROP_IMPLNAME = "implName";

    /**
     * Initialize the plugin.
     * @exception EBaseException Initialization failed.
     */
    public void init(IPublisherProcessor processor, IConfigStore
        config) throws EBaseException;

    /**
     * Returns the implementation name.
     */
    public String getImplName();

    /**
     * Returns the description of the ldap publisher.
     */
    public String getDescription();

    /**
     * Sets the instance name.
     */
    public void setInstanceName(String name);

    /**
     * Returns the instance name.
     */
    public String getInstanceName();

    /**
     * Returns the current instance parameters.
     */
    public Vector getInstanceParams();

    /**
     * Returns the initial default parameters.
     */
    public Vector getDefaultParams();

    /**
     * Returns true if the rule is enabled, false if it's disabled.
     */
    public boolean enabled();
}

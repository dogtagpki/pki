/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.topology.ug;

import com.netscape.management.client.*;
import netscape.ldap.*;

/**
  * Defines a plugin that appears under the Tools menu when
  * the User Group page is selected.
  *
  * The plugin must be registered in LDAP under this entry:
  * cn=UserGroupTools, ou=[AS version], ou=Admin, ou=Global Preferences, ou=[domain], o=NetscapeRoot
  *
  * For example,
  * dn: cn=UserGroupTools, ou=1.0, ou=Admin, ou=Global Preferences, ou=mcom.com, o=NetscapeRoot
  * cn: UserGroupTools
  * objectclass: top
  * objectclass: nsAdminObject
  * nsclassname: UGToolPlugin
  */
public interface IUGToolPlugin {
    /**
      * Initializes plugin.  Called when UG page is first selected.
      *
      * @param ldc  the active ldap connection used by this console.
      */
    public void initialize(IPage page, LDAPConnection ldc);

    /**
     * Returns short one or two word name for this plugin.
     * This name is displayed as an item in the Tools menu.
     *
     * @return name string
     */
    public String getName();

    /**
     * Returns a sentence long string describing the purpose.
     *
     * @return description string
     */
    public String getDescription();

    /**
     * Called when plugin needs to be activated.
     */
    public void run();
}

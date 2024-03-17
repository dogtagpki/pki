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
package com.netscape.management.client.topology;

import javax.swing.tree.*;
import netscape.ldap.*;

/**
 * Defines properties and methods for custom view plugin
 * for topology tree
 */
public interface ICustomView {
    /**
      * initialize. The custom view plugin can initialize all the
      * internal variable inside this routine.
      *
      * @param ldc LDAP connection
      * @param customViewDN the full DN of the custom view
      */
    public abstract void initialize(LDAPConnection ldc,
            String customViewDN);

    /**
     * get the display name of the custom view
     *
     * @return display name of the custom view
     */
    public abstract String getDisplayName();

    /**
     * get the tree model of the custom view
     *
     * @return TreeModel of the custom view
     */
    public abstract TreeModel getTreeModel();

    /**
     * set the custom view tree model
     *
     * @param newModel new tree model
     */
    public abstract void setTreeModel(TreeModel newModel);
}

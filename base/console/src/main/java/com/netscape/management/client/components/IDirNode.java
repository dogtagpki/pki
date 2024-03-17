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
package com.netscape.management.client.components;
import javax.swing.Icon;
import netscape.ldap.LDAPEntry;

/**
 *  Directory Server Directory Entry interface.
 *
 * @author  rweltman
 * @version %I%, %G%
 */

public interface IDirNode extends javax.swing.tree.TreeNode,
                                  javax.swing.tree.MutableTreeNode {

    /**
      * Specifies the name for this object, displayed in tree, right of icon.
      *
      * @return a string representing the object's name
      */
    public String getName();

    /**
     * Specifies an icon for this object, displayed in tree, left of name.
     * The recommended size for this icon is 16x16 pixels.
     *
     * @return an icon representing the object's icon
     */
    public Icon getIcon();

    /**
     * Get the DN of the entry corresponding to this node
     *
     * @return the DN of the node
     */
    public String getDN();

    /**
     * Set the DN of the node
     *
     * @param dn the new DN of the node
     */
    public void setDN( String dn );

    /**
     * Report the entry associated with this node. If the entry has not been
     * retrieved from the Directory yet, it is done now.
     *
     * @return the entry associated with this node. Only a few attributes are
     * retrieved in the entry.
     */
    public LDAPEntry getEntry();

    /**
     * Set the entry for this node
     *
     * @param entry the new entry. May be null to force reinitialization.
     */
    public void setEntry( LDAPEntry entry );

    /**
     * Returns true if the node has read its entry from the Directory
     *
     * @return true if the node has read its entry from the Directory
     */
    public boolean isLoaded();

    /**
     *  Create all the one level depth child nodes
     */
    public void reload();

    /**
     * Initialize the node from data in an entry
     *
     * @param entry An entry initialized with data
     */
    public void initializeFromEntry( LDAPEntry findEntry );

    /**
     *  Check if there are children to this node.
     */
    public void load();

    /**
     * Report if this node is considered a container. This is true if it is
     * one of a defined list of objectclasses, or if it has children.
     *
     * @return true if the node is considered a container.
     */
    public boolean isContainer();
}


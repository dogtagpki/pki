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
import java.util.Hashtable;
import netscape.ldap.LDAPSchema;
import netscape.ldap.LDAPConnection;

/**
 *  
 *
 * @author  rweltman
 * @version %I%, %G%
 */

public interface IDirModel extends javax.swing.tree.TreeModel {
    /**
     * Get a connection to the Directory instance
     *
     * @return A connection to the server
     */
    public LDAPConnection getLDAPConnection();

    /**
     * Sets the server connection used to populate the tree.
     *
     * @param ldc the server connection used to populate the tree
     */
    public void setLDAPConnection( LDAPConnection ldc );

    /**
     * Get the schema of the Directory instance
     *
     * @return A reference to a schema object.
     */
    public LDAPSchema getSchema();

    /**
     * Sets a reference to the schema of the Directory instance
     *
     * @param schema A reference to a schema object.
     */
    public void setSchema( LDAPSchema schema );

    /**
     * Get the parameter which determines if the
     * ManagedSAIT control is sent with each search. If the
     * control is sent, referral entries are returned as
     * normal entries and not followed.
     *
     * @return true if referrals are to be followed
     */
    public boolean getReferralsEnabled();

    /**
     * Set a parameter for future searches, which determines if the
     * ManagedSAIT control is sent with each search. If referrals are
     * disabled, the control is sent and you will receive the referring
     * entry back.
     *
     * @param on true (the default) if referrals are to be followed
     */
    public void setReferralsEnabled( boolean on );

    /**
     * Reports if the model is currently configured to show
     * leaf (as well as container) nodes.
     *
     * @return true if the model is currently configured to
     * show leaf (as well as container) nodes.
     */
    public boolean getAllowsLeafNodes();

    /**
     * Determines if the model is to show leaf (as well as
     * container) nodes.
     *
     * @param allow true if the model is to show leaf (as
     * well as container) nodes.
     */
    public void setAllowsLeafNodes( boolean allow );

    /**
     * Used between DirNode and DirModel, to manage the search
     * filter used to find children of a node.
     *
     * @return The search filter to be used to find direct children
     */
    public String getChildFilter();

    /**
     * Set the search filter used to find children of a node.
     *
     * @param filter The search filter to be used to find
     * direct children
     */
    public void setChildFilter( String filter );

    /**
     * Report if the model will show private suffixes.
     * If true (the default), private suffixes will appear.
     *
     * @return true if private suffixes are to be displayed in the tree
     */
    public boolean getShowsPrivateSuffixes();

    /**
     * Determines if the model will supply node objects for tree nodes.
     * If false (the default), only container nodes will appear.
     *
     * @param allow true if leaf nodes are to be displayed in the tree
     */
    public void setShowsPrivateSuffixes( boolean showPrivate );

    /**
     * Used between DirNode and DirModel, to manage the list of
     * objectclasses which are to be considered containers.
     *
     * @return A hashtable containing objectclasses to be
     * considered containers
     */
    public Hashtable getContainers();

    /**
     * Informs the tree that a particular node's structure
     * has changed and its view needs to be updated.
     *
     * @param node The node which has changed
     **/
    public void fireTreeStructureChanged( IDirNode node );
}

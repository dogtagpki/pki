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
package com.netscape.management.client;

import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;

/**
 * Defines properties and functionality of a tree node
 * of a ResourcePage tab in Console.
 *
 * This object can optionally implement the IMenuInfo
 * interface to populate menu items in the Console window.
 *
 * This class is responsible for:
 * - providing properties of a tree node
 * - receiving event notifications
 *
 * @see ResourceObject
 */
public interface IResourceObject extends TreeNode {
    /**
      * Specifies the name for this object, displayed in tree, right of icon.
      *
      * @return a string representing the object's name
      */
    public abstract String getName();

    /**
     * Specifies an icon for this object, displayed in tree, left of name.
     * The recommended size for this icon is 16x16 pixels.
     *
     * @return an icon representing the object's icon
     */
    public abstract Icon getIcon();

    /**
     * Specifies a large icon for this object.  It may be
     * displayed in a toolbar, shortcut bar, or similar UI.
     * The recommended size for this icon is 32x32 pixels.
     *
     * @return a large size icon representing the object's icon
     */
    public abstract Icon getLargeIcon();

    /**
     * Returns object that renders right hand panel contents
     * for this tree node.
     *
     * @return a Component object that
     */
    public abstract Component getCustomPanel();

    /**
     * Notification that this node has been unselected in the tree.
     *
     * @param viewInstance		IPage instance which calls this method
     */
    public abstract void unselect(IPage viewInstance);

    /**
     * Notification that this node has been selected in the tree.
     *
     * @param viewInstance		IPage instance which calls this method
     */
    public abstract void select(IPage viewInstance);

    /**
     * Notification that this object needs to execute an action.
     * Called when user double clicks on a tree node.  For example, called when
     * user drills down to server instance, then double-clicks on it to launch
     * Server window.
     *
     * @param viewInstance		IPage instance which calls this method
     * @return boolean value indicating whether run action completed succesfully
     */
    public abstract boolean run(IPage viewInstance,
            IResourceObject selection[]);

    /**
     * An inquiry about whether this object can execute 'run' action
     * on behalf all the multiple selected objects in tree.
     *
     * If return is true, the run method will be called (only on this node)
     *
     * @param selection			array of IResourceObjects currently selected in tree
     * @return boolean value indicating whether object can execute 'run' method
     */
    public abstract boolean canRunSelection(IResourceObject selection[]);
}

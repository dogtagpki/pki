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

import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.console.*;

/**
  * Defines a task entry to be displayed in the TaskPage.
  * This object can implement IMenuInfo interface to populate menu items.
  *
  * Implementations of this object may implement IMenuInfo to populate menu items.
  *
  * @see com.sun.java.swing.tree.TreeNode
  */
public interface ITaskObject extends TreeNode {
    /**
      * Returns short name (title) for this task.
         * Called by: TaskModel
      */
    public abstract String getName();

    /**
     *	Returns icon for this task.
     */
    public abstract Icon getIcon();

    /**
     * Returns description for this task.  Used in VIEW_DETAIL view type.
        * Called by: TaskModel
     */
    public abstract String getDescription();

    /**
     * Return console information.
        * Called by: TaskModel
     */
    public abstract ConsoleInfo getConsoleInfo();

    /**
     * Called when this object is unselected.
        * Called by: TaskModel
     */
    public abstract void unselect(IPage viewInstance);

    /**
     * Called when this object is selected.
        * Called by: TaskModel
     */
    public abstract void select(IPage viewInstance);

    /**
        * Called when this object needs to execute, (when user double-clicks or menu Open)
     * @return success or failure of run operation
        * Called by: TaskModel
     */
    public abstract boolean run(IPage viewInstance);
}

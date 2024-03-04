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
 * Default implementation of ITaskObject.
 * Defines a task entry to be displayed in the TaskPage.
 * Subclasses of this object may implement IMenuInfo to populate menu items.
 *
 * @see ITaskObject
 * @see DefaultMutableTreeNode
 */
public class TaskObject extends DefaultMutableTreeNode implements ITaskObject {
    protected String _name;
    protected String _description;
    protected String _dn;
    protected Icon _icon;
    protected ConsoleInfo _consoleInfo;

    /**
     *	Creates empty task object.
     */
    public TaskObject() {
        super();
    }

    /**
     *	Creates task object with specified name.
     */
    public TaskObject(String name) {
        this();
        _name = name;
    }

    /**
     *	Creates task object with specified name.
     */
    public TaskObject(String name, Icon icon) {
        this();
        _name = name;
        _icon = icon;
    }

    /**
     *	Creates task object with specified name.
     */
    public TaskObject(String name, ConsoleInfo ci) {
        this(name);
        _consoleInfo = ci;
    }

    /**
     *	Returns name of this task.
     */
    public String getName() {
        return _name;
    }

    /**
     *	Sets name for this task
     */
    public void setName(String name) {
        _name = name;
    }

    /**
     *	Returns icon for this task.
     */
    public Icon getIcon() {
        return _icon;
    }

    /**
     *	Sets icon for this task
     */
    public void setIcon(Icon icon) {
        _icon = icon;
    }

    public String toString() {
        return getName();
    }

    /**
     *	Returns description for this task.  Used in VIEW_DETAIL view type.
     */
    public String getDescription() {
        return _description;
    }

    /**
     *	Sets description for this task.
     */
    public void setDescription(String description) {
        _description = description;
    }

    /**
     *	Sets console information.  Called by TaskPage.createTaskModel()
     *  when this object is created.
     */
    public void setConsoleInfo(ConsoleInfo newConsoleInfo) {
        _consoleInfo = newConsoleInfo;
    }

    /**
     *	gets console information.
     */
    public ConsoleInfo getConsoleInfo() {
        return _consoleInfo;
    }

    /**
     * Called when this object is unselected.
     * Called by: TaskModel
     */
    public void unselect(IPage viewInstance) {
    }

    /**
     * Called when this object is selected.
     * Called by: TaskModel
     */
    public void select(IPage viewInstance) {
    }

    /**
     * Called when this object is run.
     * @return sucess or failure indication
     * Called by: TaskModel
     */
    public boolean run(IPage viewInstance) {
        return false;
    }

    /**
     * sends ITaskModelListener.removeMenuItems() notifications to 
     * all listeners
     **/
    public void fireRemoveMenuItems(IPage viewInstance,
            IMenuInfo menuInfo) {
        if (viewInstance instanceof TaskPage) {
            TaskPage taskPage = (TaskPage) viewInstance;
            ITaskModel model = taskPage.getModel();
            if (model instanceof TaskModel) {
                TaskModel taskModel = (TaskModel) model;
                taskModel.fireRemoveMenuItems(viewInstance, menuInfo);
            }
        }
    }

    /**
     * sends ITaskModelListener.addMenuItems() notifications to all listeners
     **/
    public void fireAddMenuItems(IPage viewInstance, IMenuInfo menuInfo) {
        if (viewInstance instanceof TaskPage) {
            TaskPage taskPage = (TaskPage) viewInstance;
            ITaskModel model = taskPage.getModel();
            if (model instanceof TaskModel) {
                TaskModel taskModel = (TaskModel) model;
                taskModel.fireAddMenuItems(viewInstance, menuInfo);
            }
        }
    }

    /**
     * sends ITaskModelListener.disableMenuItem() notifications to 
     * all listeners
     **/
    public void fireDisableMenuItem(IPage viewInstance, String menuItemID) {
        if (viewInstance instanceof TaskPage) {
            TaskPage taskPage = (TaskPage) viewInstance;
            ITaskModel model = taskPage.getModel();
            if (model instanceof TaskModel) {
                TaskModel taskModel = (TaskModel) model;
                taskModel.fireDisableMenuItem(viewInstance, menuItemID);
            }
        }
    }

    /**
     * sends ITaskModelListener.enableMenuItem() notifications to all listeners
     **/
    public void fireEnableMenuItem(IPage viewInstance, String menuItemID) {
        if (viewInstance instanceof TaskPage) {
            TaskPage taskPage = (TaskPage) viewInstance;
            ITaskModel model = taskPage.getModel();
            if (model instanceof TaskModel) {
                TaskModel taskModel = (TaskModel) model;
                taskModel.fireEnableMenuItem(viewInstance, menuItemID);
            }
        }
    }

    /**
     * sends fireChangeStatusItemState() notifications to all listeners
     **/
    public void fireChangeStatusItemState(IPage viewInstance,
            String statusItemID, Object state) {
        if (viewInstance instanceof TaskPage) {
            TaskPage taskPage = (TaskPage) viewInstance;
            ITaskModel model = taskPage.getModel();
            if (model instanceof TaskModel) {
                TaskModel taskModel = (TaskModel) model;
                taskModel.fireChangeStatusItemState(viewInstance,
                        statusItemID, state);
            }
        }
    }
}

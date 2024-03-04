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

import javax.swing.tree.TreeModel;

/**
 * Defines the data model for TaskPage; responsible for providing:
 * - data for task list (using methods inherited from TreeModel)
 * - right hand panel for each tree node
 * - sending events (via ITaskModelListener)
 * - receiving events (via action methods)
 *
 * @see ITaskModelListener
 * @see TaskModel
 */
public interface ITaskModel extends TreeModel {
    /**
      * Constant representing a view that shows
      * each task with a name and description.
      *
     * @deprecated multiple task views not supported
      */
    @Deprecated
    public static final int VIEW_DETAIL = 0;

    /**
     * Constant representing a view that shows
     * each task with a name only.
     *
    * @deprecated multiple task views not supported
     */
    @Deprecated
    public static final int VIEW_BRIEF = 1;

    /**
     * Registers a listener that is interested in receiving events.
     * Typically will be called by TaskPage.
     *
     * @param l		IResourceModelListener to be added to listener list
     */
    public abstract void addITaskModelListener(ITaskModelListener l);

    /**
     * Deregisters a listener previously added by the
     * addIResourceModelListener method.
     *
     * @param l		IResourceModelListener to be removed from listener list
     */
    public abstract void removeITaskModelListener(ITaskModelListener l);

    /**
     * Returns total number of views supported by this model.
     *
     * @deprecated multiple task views not supported
     */
    @Deprecated
    public abstract int getViewCount();

    /**
     * Returns name of specified view.  The name is used in a number of
    * places such as the Task menu, possibly a drop down view selector
    * combo box, and the task customization dialog.
    *
    * @deprecated multiple task views not supported
     */
    @Deprecated
    public abstract String getViewName(int viewIndex);

    /**
     * Returns a VIEW_* constant for the specified view
     *
    * @deprecated multiple task views not supported
     */
    @Deprecated
    public abstract int getViewType(int viewIndex);

    /**
      * Returns root node for the specified view.
    * Note: TreeModel.getRoot() is not called.
    * Called by TaskPage
      */
    public abstract Object getViewRoot(int viewIndex);

    /**
     * Notification that one or more tasks have been selected in task list.
     *
     * @param viewInstance		IPage instance which calls this method
     * @param selection			array of ITaskObjects currently selected in tree
     * @param previousSelection	array of ITaskObjects previously selected in tree
     */
    public abstract void actionObjectSelected(IPage viewInstance,
            ITaskObject selection, ITaskObject previousSelection);

    /**
     * Notification that 'run' action should be performed on the selected task.
     * Called when user double clicks on a task.
     *
     * @param viewInstance		IPage instance which calls this method
     * @param selection			array of ITaskObjects currently selected in tree
     */
    public abstract void actionObjectRun(IPage viewInstance,
            ITaskObject selection);

    /**
     * Notification from Console that window is closing.
     * (in response to a Close or Exit selection).
     * In response, a CloseVetoException may be thrown which
     * causes Console to inform user that there is unsaved
     * data in this tab, and allows user to abort close operation.
     *
     * @param parent				IFramework parent of this object
     * @exception CloseVetoException thrown to veto the close action.
     */
    public abstract void actionViewClosing(IPage viewInstance)
            throws CloseVetoException;
}

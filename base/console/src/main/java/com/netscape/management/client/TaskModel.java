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

import java.util.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;

/**
 * Implements a data model for TaskPage; responsible for providing:
 * - data for task list (using methods inherited from TreeModel)
 * - right hand panel for each tree node
 * - sending events (via ITaskModelListener)
 * - receiving events (via action methods)
 *
 * @see ITaskModelListener
 * @see ITaskModel
 */
public class TaskModel implements ITaskModel {
    ConsoleInfo _consoleInfo = null;
    ITaskObject _root;
    Vector _listeners = new Vector();

    /**
     *      Constructs empty TaskModel.
     */
    public TaskModel() {
    }

    /**
     *      Constructs TaskModel with consoleinfo set.
     */
    public TaskModel(ConsoleInfo info) {
        _consoleInfo = info;
    }

    /**
     * Constructs TaskModel set with root task object.
     * The root task object is an anchor (placeholder) for all other tasks.
     * The root task object is not displayed in the task list.
     */
    public TaskModel(ITaskObject root) {
        setRoot(root);
    }

    /**
     * Sets the root task object for the default view.  If you support
     * multiple views, you must maintain your own list of root objects,
     * and return the correct root object in getViewRoot(viewIndex).
     * This requires you to subclass getViewRoot().
     * TODO: add setRoot(int viewIndex, ITaskObject root);
     */
    public void setRoot(ITaskObject root) {
        _root = root;
    }

    /**
     * Returns root task object in the task list hierarchy.
     * This method is not called directly.
     */
    public Object getRoot() {
        return _root;
    }

    /**
     *      Returns child node at specified index, from a given parent node.
     */
    public Object getChild(Object node, int index) {
        return ((ITaskObject) node).getChildAt(index);
    }

    /**
     *      Returns index of of specified child node.
     */
    public int getIndexOfChild(Object parent, Object child) {
        return ((ITaskObject) parent).getIndex((ITaskObject) child);
    }

    /**
     *      Returns number of children of specified node.
     */
    public int getChildCount(Object node) {
        return ((ITaskObject) node).getChildCount();
    }

    /**
     *      Returns true if node is a leaf node (e.g., has no children)
     */
    public boolean isLeaf(Object node) {
        return (((ITaskObject) node).getChildCount() == 0);
    }

    /**
     * Adds a listener that is interested in receiving TreeModel events.
     * Called by JTree.
     */
    public void addTreeModelListener(TreeModelListener l) {
    }

    /**
     * Removes a listener that is interested in receiving TreeModel events.
     * Called by JTree.
     */
    public void removeTreeModelListener(TreeModelListener l) {
    }

    /**
     *      Called when user has altered the value for the item identified by path to newValue.
     */
    public void valueForPathChanged(TreePath path, Object newValue) {
    }

    /**
     * Returns list of registered ITaskModelListeners for this model.
     * TODO: use EventListenerList to store listener list
     * TODO: rename to getModelListenerList()
     * Called by subclassed ResourceModel
     */
    public Enumeration getModelListeners() {
        return _listeners.elements();
    }

    /**
     * Adds a listener that is interested in receiving ITaskModelListener events.
     * Called by TaskPage
     */
    public void addITaskModelListener(ITaskModelListener l) {
        _listeners.addElement(l);
    }

    /**
     * Removes a listener that is interested in receiving ITaskModelListener events.
     * Called by TaskPage
     */
    public void removeITaskModelListener(ITaskModelListener l) {
        _listeners.removeElement(l);
    }

    /**
     * Returns the number of views supported by this page model.
     * TODO: currently returns 0.  This is because view loading and
     * customization is not ready.  You must subclass this method if
     * you support more than one view.
     * Note 02/01/98: the multiple view concept is dead, UI decision
     */
    public int getViewCount() {
        return 0;
    }

    /**
     * Returns name of specified view.  The name is used in a number of
     * places such as the Task menu, possibly a drop down view selector
     * combo box, and the task customization dialog.
     * Note 02/01/98: the multiple view concept is dead, UI decision
     */
    public String getViewName(int viewIndex) {
        return (String) null;
    }

    /**
     * Returns a VIEW_* constant for the specified view.
     * Note 02/01/98: the multiple view concept is dead, UI decision
     */
    public int getViewType(int viewIndex) {
        return ITaskModel.VIEW_DETAIL;
    }

    /**
     * Returns root node for the specified view.
     * Note: TreeModel.getRoot() is not directly called.
     * Note 02/01/98: the multiple view concept is dead, UI decision
     */
    public Object getViewRoot(int viewIndex) {
        return getRoot();
    }

    /**
     *  sends ITaskModelListener.addStatusItem() notifications to all listeners
     */
    public void fireAddStatusItem(IPage viewInstance, IStatusItem item) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.addStatusItem(new TaskModelEvent(this, viewInstance, item));
        }
    }

    /**
     *  sends ITaskModelListener.removeStatusItem() notifications to all listeners
     **/
    public void fireRemoveStatusItem(IPage viewInstance, IStatusItem item) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.removeStatusItem(
                    new TaskModelEvent(this, viewInstance, item));
        }
    }

    /**
     *  sends ITaskModelListener.changeStatusItemState() notifications to all listeners
     **/
    public void fireChangeStatusItemState(IPage viewInstance,
            String itemID, Object state) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.changeStatusItemState(
                    new TaskModelEvent(this, viewInstance, itemID, state));
        }
    }

    /**
     *  sends ITaskModelListener.changeFeedbackCursor() notifications to all listeners
     */
    public void fireChangeFeedbackCursor(IPage viewInstance,
            int feedbackIndicatorType) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.changeFeedbackCursor( new TaskModelEvent(this, viewInstance,
                    new FeedbackIndicator(feedbackIndicatorType)));
        }
    }

    /**
     * sends ITaskModelListener.removeMenuItems() notifications to all listeners
     **/
    public void fireRemoveMenuItems(IPage viewInstance,
            IMenuInfo menuInfo) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.removeMenuItems(
                    new TaskModelEvent(this, viewInstance, menuInfo));
        }
    }

    /**
     * sends ITaskModelListener.addMenuItems() notifications to all listeners
     **/
    public void fireAddMenuItems(IPage viewInstance, IMenuInfo menuInfo) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.addMenuItems(
                    new TaskModelEvent(this, viewInstance, menuInfo));
        }
    }

    /**
     * sends ITaskModelListener.disableMenuItem() notifications to all listeners
     **/
    public void fireDisableMenuItem(IPage viewInstance, String menuItemID) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.disableMenuItem(
                    new TaskModelEvent(this, viewInstance, menuItemID));
        }
    }

    /**
     * sends ITaskModelListener.enableMenuItem() notifications to all listeners
     **/
    public void fireEnableMenuItem(IPage viewInstance, String menuItemID) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            ITaskModelListener l = (ITaskModelListener) e.nextElement();
            l.enableMenuItem(
                    new TaskModelEvent(this, viewInstance, menuItemID));
        }
    }

    /**
     * Notification that task object was selected in the task list.
     */
    public void actionObjectSelected(IPage viewInstance,
            ITaskObject selection, ITaskObject previousSelection) {
        if (previousSelection != null) {
            if (selection != previousSelection) {
                previousSelection.unselect(viewInstance);
            }
        }

        if (selection != null) {
            selection.select(viewInstance);
        }
    }

    /**
     * Notification that selected task object needs to run.
     */
    public void actionObjectRun(IPage viewInstance, ITaskObject selection) {
        if (selection != null) {
            Debug.println(Debug.TYPE_RSPTIME,
                    "Run Task " + selection.getName() + " ...");
            selection.run(viewInstance);
        }
    }


    /**
     * Notification that the framework window is closing.
     * Called by ResourcePage
     */
    public void actionViewClosing(IPage viewInstance)
            throws CloseVetoException {
    }

    //parser to extract SIE for KC related tasks
    //after we got task/config window current dn will be
    //the sie it self.  and the first cn will be server-id-host
    static String getSIE(ConsoleInfo consoleInfo) {
        String currentDN = consoleInfo.getCurrentDN();
        return currentDN.substring(currentDN.indexOf("cn=") + 3,
                currentDN.indexOf(","));
    }
}

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
import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;


/**
 * Implements data model for ResourcePage; responsible for providing:
 * - data for tree nodes (using methods inherited from TreeModel)
 * - right hand panel for each tree node
 * - sending events (via IResourceModelListener)
 * - receiving events (via action methods)
 *
 * @see IResourceModel
 */
public class ResourceModel implements IResourceModel {
    protected IResourceObject _root;
    protected Vector _listeners = new Vector(); // TODO: use EventListenerList for this
    protected EventListenerList _listenerList = new EventListenerList();
    private boolean _rootVisible;

    /**
     * Returns empty ResourceModel.
     */
    public ResourceModel() {
    }

    /**
      * Returns ResourceModel set with root tree node.
      */
    public ResourceModel(IResourceObject root) {
        _root = (IResourceObject) root;
    }

    /**
      * Sets root node of the tree.
      */
    public void setRoot(Object root) {
        _root = (IResourceObject) root;
    }

    /**
      * Sets visisbility of root node.
      */
    public void setRootVisible(boolean visible) {
        _rootVisible = visible;
    }

    /**
      * Returns root node of the tree.
      * Called by ResourcePage
      */
    public Object getRoot() {
        return _root;
    }

    /**
      * Returns whether root node is visible
      * Called by ResourcePage
      */
    public boolean isRootVisible() {
        return _rootVisible;
    }

    /**
      * Returns the child node at specified index, from a given parent node.
      * Called by ResourcePage
      */
    public Object getChild(Object node, int index) {
        return ((IResourceObject) node).getChildAt(index);
    }

    /**
      * Returns the child node at specified index, from a given parent node.
      * Called by ResourcePage
      */
    public int getIndexOfChild(Object parent, Object child) {
        return ((IResourceObject) parent).getIndex(
                (IResourceObject) child);
    }

    /**
      * Returns number of children of specified node.
      * Called by ResourcePage
      */
    public int getChildCount(Object node) {
        return ((IResourceObject) node).getChildCount();
    }

    /**
      * Returns true if node is a leaf node (in this case: has no children)
      * Called by ResourcePage
      */
    public boolean isLeaf(Object node) {
        return (((IResourceObject) node).isLeaf());
    }

    /**
     * Returns the detail panel associated with the specified node.
     * Called by ResourcePage
      */
    public Component getCustomPanel(IPage viewInstance,
            IResourceObject node) {
        Component customPanel = node.getCustomPanel();
        if (customPanel == null) {
            customPanel = new JPanel();
        }
        return customPanel;
    }

    /**
     * Adds a listener that is interested in receiving TreeModelListener events.
     * Called by JTree.
      */
    public void addTreeModelListener(TreeModelListener l) {
        _listenerList.add(TreeModelListener.class, l);
            }

            /**
               * Removes a listener that is interested in receiving TreeModelListener events.
             * Called by JTree.
               */
    public void removeTreeModelListener(TreeModelListener l) {
        _listenerList.remove(TreeModelListener.class, l);
            }

            /**
              * deprecated replaced by fireTreeNodesChanged
             **/
    public void nodeChanged(ResourceObject node) {
        fireTreeNodeChanged(node);
    }


    /**
      * Informs the tree that a particular resource object has changed
      * and its view needs to be updated.
      * Called by serverloc\StatusThread.java
      * @see EventListenerList
     **/
    public void fireTreeNodeChanged(ResourceObject node) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == TreeModelListener.class) {
                // Lazily create the event:
                if (e == null)
                    e = new TreeModelEvent(this, node.getPath());
                ((TreeModelListener) listeners[i + 1]).treeNodesChanged(e);
            }
        }
    }

    /**
      * Informs the tree that a particular resource object has changed
      * and its view needs to be updated.
      * Called by serverloc\StatusThread.java
      * @see EventListenerList
     **/
    public void fireSelectTreeNode(IPage viewInstance,
            ResourceObject node) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.selectTreeNode( new ResourceModelEvent(this, viewInstance,
                    node.getPath()));
        }
    }

    /**
      * Informs the tree that a particular resource object has changed
      * and its view needs to be updated.
      * Called by serverloc\StatusThread.java
      * @see EventListenerList
     **/
    public void fireExpandTreeNode(IPage viewInstance,
            ResourceObject node) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.expandTreeNode( new ResourceModelEvent(this, viewInstance,
                    node.getPath()));
        }
    }

    /**
      * Informs tree that a particular resource object's structure has changed
      * and its view needs to be updated.
      * @see EventListenerList
     **/
    public void fireTreeStructureChanged(ResourceObject node) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == TreeModelListener.class) {
                // Lazily create the event:
                if (e == null)
                    e = new TreeModelEvent(this, node.getPath());
                ((TreeModelListener) listeners[i + 1]).
                        treeStructureChanged(e);
            }
        }
    }

    /**
      * Called when user has altered the value for the item identified by path to newValue.
      * Called by JTree
     **/
    public void valueForPathChanged(TreePath path, Object newValue) {
    }

    /**
         * Returns list of registered IResourceModelListeners for this model.
      * TODO: use EventListenerList to store listener list
      * TODO: rename to getModelListenerList()
     **/
    public Enumeration getModelListeners() {
        return _listeners.elements();
    }

    /**
      *  sends IResourceModelListener.addStatusItem() notifications to all listeners
      */
    public void fireAddStatusItem(IPage viewInstance, IStatusItem item) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.addStatusItem(
                    new ResourceModelEvent(this, viewInstance, item));
        }
    }

    /**
      *  sends IResourceModelListener.removeStatusItem() notifications to all listeners
     **/
    public void fireRemoveStatusItem(IPage viewInstance, IStatusItem item) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.addStatusItem(
                    new ResourceModelEvent(this, viewInstance, item));
        }
    }

    /**
      *  sends IResourceModelListener.changeStatusItemState() notifications to all listeners
     **/
    public void fireChangeStatusItemState(IPage viewInstance,
            String itemID, Object state) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.changeStatusItemState(
                    new ResourceModelEvent(this, viewInstance, itemID,
                    state));
        }
    }

    /**
      *  sends IResourceModelListener.changeFeedbackCursor() notifications to all listeners
      */
    public void fireChangeFeedbackCursor(IPage viewInstance,
            int feedbackIndicatorType) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.changeFeedbackCursor(
                    new ResourceModelEvent(this, viewInstance,
                    new FeedbackIndicator(feedbackIndicatorType)));
        }
    }

    /**
       * sends IResourceModelListener.removeMenuItems() notifications to all listeners
     **/
    public void fireRemoveMenuItems(IPage viewInstance,
            IMenuInfo menuInfo) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.removeMenuItems(
                    new ResourceModelEvent(this, viewInstance, menuInfo));
        }
    }

    /**
       * sends IResourceModelListener.addMenuItems() notifications to all listeners
     **/
    public void fireAddMenuItems(IPage viewInstance, IMenuInfo menuInfo) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.addMenuItems(
                    new ResourceModelEvent(this, viewInstance, menuInfo));
        }
    }

    /**
       * sends IResourceModelListener.disableMenuItem() notifications to all listeners
     **/
    public void fireDisableMenuItem(IPage viewInstance, String menuItemID) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.disableMenuItem( new ResourceModelEvent(this, viewInstance,
                    menuItemID));
        }
    }

    /**
       * sends IResourceModelListener.enableMenuItem() notifications to all listeners
     **/
    public void fireEnableMenuItem(IPage viewInstance, String menuItemID) {
        Enumeration e = getModelListeners();
        while (e.hasMoreElements()) {
            IResourceModelListener l =
                    (IResourceModelListener) e.nextElement();
            l.enableMenuItem( new ResourceModelEvent(this, viewInstance,
                    menuItemID));
        }
    }

    /**
         * Adds a listener that is interested in receiving IResourceModelListener.
      * Called by ResourcePage
      */
    public void addIResourceModelListener(IResourceModelListener l) {
        _listeners.addElement(l);
    }

    /**
         * Removes a listener that is interested in receiving IResourceModelListener.
      * Called by ResourcePage
      */
    public void removeIResourceModelListener(IResourceModelListener l) {
        _listeners.removeElement(l);
    }

    /**
       * Notification that objects have been selected in the tree.
     * The selection represents a list of all highlighted objects in the tree,
     * not just a list of objects selected since the last notification.
     * Called by ResourcePage.
       */
    public void actionObjectSelected(IPage viewInstance,
            IResourceObject[] selection,
            IResourceObject[] previousSelection) {
        // optimization: don't do anything if selection == previousSelection
        if (selection != null && previousSelection != null &&
                selection.length == previousSelection.length) {
            boolean duplicateSet = true;
            for (int i = 0; i < previousSelection.length; i++) {
                if (selection[i] != previousSelection[i]) {
                    duplicateSet = false;
                    break;
                }
            }
            if (duplicateSet) {
                return;
            }
        }

        if ((previousSelection != null) && (previousSelection.length > 0)) {
            String className = previousSelection[0].getClass().getName();
                    boolean objectsOfSameClass = true;
            for (int i = 1; i < previousSelection.length; i++) {
                if (className.equals(
                        previousSelection[i].getClass().getName()) ==
                        false) {
                    objectsOfSameClass = false;
                    break;
                }
            }

            for (int i = 0; i < previousSelection.length; i++) {
                previousSelection[i].unselect(viewInstance);
                // Only need to do this for the first one since only similar objects
                // can be multiply selected. In the object's actionMenuSelected()
                // method, multiple selection case should be handled!!!
                if ((i == 0) && (objectsOfSameClass == true) &&
                        (previousSelection[i] instanceof IMenuInfo)) {
                    fireRemoveMenuItems(viewInstance,
                            (IMenuInfo) previousSelection[i]);
                }
            }
        }

        if ((selection != null) && (selection.length > 0)) {
            String className = selection[0].getClass().getName();
                    boolean objectsOfSameClass = true;
            for (int i = 1; i < selection.length; i++) {
                if (className.equals(selection[i].getClass().getName())
                        == false) {
                    objectsOfSameClass = false;
                    break;
                }
            }

            for (int j = 0; j < selection.length; j++) {
                selection[j].select(viewInstance);
                // Only need to do this for the first one since only similar objects
                // can be multiply selected. In the object's actionMenuSelected()
                // method, multiple selection case should be handled!!!
                if ((j == 0) && (objectsOfSameClass == true) &&
                        (selection[j] instanceof IMenuInfo)) {
                    fireAddMenuItems(viewInstance,
                            (IMenuInfo) selection[j]);
                }
            }
        }
    }

    /**
       * Notification that a run action (aka: execute, perform) needs to be
     * taken on the selected objects.
       */
    public void actionObjectRun(IPage viewInstance,
            IResourceObject[] selection) {
        if (selection != null) {
            fireChangeFeedbackCursor(viewInstance,
                    FeedbackIndicator.FEEDBACK_WAIT);
            if (selection.length == 1) {
                selection[0].run(viewInstance, selection);
            } else {
                // multiple selections
                boolean isManagable = true;
                for (int i = 0; i < selection.length; i++) {
                    if (selection[i] instanceof IResourceObject) {
                        IResourceObject ro = (IResourceObject) selection[i];
                        if (!ro.canRunSelection(selection)) {
                            isManagable = false;
                            break;
                        }
                    } else {
                        isManagable = false;
                        break;
                    }
                }
                if (isManagable) {
                    // pass the whole list to the client
                    selection[0].run(viewInstance, selection);
                }
            }
            fireChangeFeedbackCursor(viewInstance,
                    FeedbackIndicator.FEEDBACK_DEFAULT);
        }
    }

    /**
       * Notification that the framework window is closing.
       * Called by ResourcePage
       */
    public void actionViewClosing(IPage viewInstance)
            throws CloseVetoException {
    }
}

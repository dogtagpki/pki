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
import javax.swing.tree.*;

/**
 * A type of EventObject that contains properties about
 * events communicating from a ResourceModel.
 *
 * @see IResourceModelListener
 */
public class ResourceModelEvent extends EventObject {
    IPage _viewInstance = null;
    IStatusItem _statusItem;
    String _statusItemID;
    Object _statusItemState;
    String _statusItemPosition = IStatusItem.LEFT;
    Cursor _cursor;
    Component _customPanel;
    String _menuID;
    IMenuInfo _menuInfo;
    TreePath _treePath;

    /**
     * Creates a generic ResourceModelEvent with no properties set
     * except for the event source.
     *
     * @param source	object that creates this event
     */
    public ResourceModelEvent(Object source) {
        super(source);
    }

    /**
      * Creates ResourceModelEvent with Cursor property set.
      * This constructor is suitable changing the feedback
      * cursor on all 'views'.
      *
      * @param source			Object that creates this event
      * @param cursor			Cursor object representing shape of mouse cursor
      * @see IResourceModelListener#changeFeedbackCursor
      */
    public ResourceModelEvent(Object source, Cursor cursor) {
        this(source, null, cursor);
    }

    /**
      * Creates ResourceModelEvent with Cursor property set.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
      * @param cursor			Cursor object representing shape of mouse cursor
      * @see IResourceModelListener#changeFeedbackCursor
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            Cursor cursor) {
        super(source);
        setViewInstance(viewInstance);
        setCursor(cursor);
    }

    /**
      * Creates ResourceModelEvent with TreePath property set.
      * This constructor is used for the selectTreeNode or expandTreeNode event.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
      * @param path				TreeNode array representing the path to a node
      * @see IResourceModelListener#selectTreeNode
      * @see IResourceModelListener#expandTreeNode
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            TreeNode[] path) {
        super(source);
        setTreePath(new TreePath(path));
    }

    /**
      * Creates ResourceModelEvent with StatusItem property set.
      * This constructor is used for removing an item from the status bar.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
      * @param item 				IStatusItem data for this event
      * @see IResourceModelListener#removeStatusItem
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            IStatusItem item) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItem(item);
    }

    /**
      * Creates ResourceModelEvent with StatusItem property set.
      * This constructor is used for adding an item to the status bar
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
      * @param item 				IStatusItem data for this event
      * @see IResourceModelListener#addStatusItem
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            IStatusItem item, String position) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItem(item);
        setStatusItemPosition(position);
    }

    /**
      * Creates ResourceModelEvent with StatusItem property set.
      * This constructor is used for changing the state of a status item.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
      * @param item 				IStatusItem data for this event
      * @see IResourceModelListener#changeStatusItemState
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            String statusItemID, Object statusItemState) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItemState(statusItemID, statusItemState);
    }

    /**
      * Creates ResourceModelEvent with MenuID property set.
      * This constructor is used to enable or disable menu items.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
         * @param menuID			string identifier representing menu item
      * @see IResourceModelListener#enableMenuItem
      * @see IResourceModelListener#disableMenuItem
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            String menuID) {
        super(source);
        setViewInstance(viewInstance);
        setMenuID(menuID);
    }

    /**
      * Creates ResourceModelEvent with MenuInfo property set.
      * This constructor is used to enable or disable menu items.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
         * @param menuID			string identifier representing menu item
      * @see IResourceModelListener#enableMenuItem
      * @see IResourceModelListener#disableMenuItem
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            IMenuInfo menuInfo) {
        super(source);
        setViewInstance(viewInstance);
        setMenuInfo(menuInfo);
    }

    /**
      * Creates ResourceModelEvent with CustomPanel property set.
      * This constructor is used to enable or disable menu items.
      *
      * @param source			Object that creates this event
      * @param viewInstance		IPage view instance which this event applies to
         * @param customPanel		Component that is displayed in the right hand pane
      * @see IResourceModelListener#changeCustomPanel
      */
    public ResourceModelEvent(Object source, IPage viewInstance,
            Component customPanel) {
        super(source);
        setViewInstance(viewInstance);
        setCustomPanel(customPanel);
    }



    /**
      * Returns the instance of Console window to which this event
      * applies to.  Currently, this method is not used.
      *
      * @return IPage view instance for this event
      */
    public IPage getViewInstance() {
        return _viewInstance;
    }

    /**
      * Sets the instance of Console window for which this event
      * applies to.  A view instance is a unique identifier that
      * represents a 'page' (tab).   Since an event is typically
      * sent in response to a change in a particular view,
      * you will want to target your event only for that view.
      * If the event is applicable to all views, the viewInstance
      * parameter can be set to null.
      */
    public void setViewInstance(IPage viewInstance) {
        _viewInstance = viewInstance;
    }

    /**
      * Returns identifer for the menu item for which this
      * event applies.
      *
      * @return a string ID
      */
    public String getMenuID() {
        return _menuID;
    }

    /**
      * Sets identifer for the menu item for which this
      * event applies.
      *
      * @param menuID	string identifier
      */
    public void setMenuID(String menuID) {
        _menuID = menuID;
    }

    /**
      * Returns an IMenuInfo object which contains references
      * to menu items for which this event applies.
      *
      * @return IMenuInfo interface which provides access to menu items.
      */
    public IMenuInfo getMenuInfo() {
        return _menuInfo;
    }

    /**
      * Sets the IMenuInfo object which contains references
      * to menu items for which this event applies.
      *
      * @param menuInfo	IMenuInfo interface which provides access to menu items
      */
    public void setMenuInfo(IMenuInfo menuInfo) {
        _menuInfo = menuInfo;
    }

    /**
      * Sets the status item for which this event applies.
      *
      * @param item		IStatusItem object for this event
      */
    public void setStatusItem(IStatusItem item) {
        _statusItem = item;
    }

    /**
      * Sets the position for the status itemfor which this event applies.
      *
      * @param position  a string constant defined in IStatusItem specifying
      *					position for this status item
      */
    public void setStatusItemPosition(String position) {
        _statusItemPosition = position;
    }

    /**
       * Get status item's position
       */
    public String getStatusItemPosition() {
        return _statusItemPosition;
    }

    /**
       * Returns status bar text.
     * Called by listener while processing statusItemStateChanged(), statusItemAdded(), statusItemDeleted()
       */
    public IStatusItem getStatusItem() {
        return _statusItem;
    }

    /**
       * Sets the state for a status item.
       * Called by ResourceModel
       */
    public void setStatusItemState(String itemID, Object state) {
        _statusItemID = itemID;
        _statusItemState = state;
    }

    /**
       * Returns the state for a status item.
     * Called by listener while processing statusItemStateChanged()
       */
    public String getStatusItemID() {
        return _statusItemID;
    }

    /**
       * Returns the state for a status item.
     * Called by listener while processing statusItemStateChanged()
       */
    public Object getStatusItemState() {
        return _statusItemState;
    }

    /**
       * Sets custom panel to be displayed on right hand pane.
       * Called by ResourceModel
       */
    public void setCustomPanel(Component customPanel) {
        _customPanel = customPanel;
    }

    /**
       * Returns custom panel to be displayed on right hand pane.
     * Called by listener while processing customPanelChanged().
       */
    public Component getCustomPanel() {
        return _customPanel;
    }

    /**
       * Returns visual cursor.
     * Called by listener while processing cursorChanged().
       */
    public Cursor getCursor() {
        return _cursor;
    }

    /**
       * Sets visual feeback cursor.
       * Called by ResourceModel
       */
    public void setCursor(Cursor cursor) {
        _cursor = cursor;
    }

    /**
       * Set IResourceObject, a tree node.
       * Called by ResourceModel
       */
    public void setTreePath(TreePath treePath) {
        _treePath = treePath;
    }

    /**
       * Get IResourceObject, a tree node.
       * Called by listener while processing IResourceListener.selectTreeNode, expandTreeNode
       */
    public TreePath getTreePath() {
        return _treePath;
    }
}

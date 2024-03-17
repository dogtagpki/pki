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

/**
 * A type of EventObject that contains properties about
 * events communicating from a TaskModel.
 *
 * @see IResourceModelListener
 */
public class TaskModelEvent extends EventObject {
    IPage _viewInstance = null;
    Cursor _cursor;
    IStatusItem _statusItem;
    String _statusItemID;
    Object _statusItemState;
    String _statusItemPosition = IStatusItem.LEFT;
    String _menuID;
    IMenuInfo _menuInfo;

    /**
     * Use with for all events.  Then call setXXX methods as appropriate.
     * Called by TaskModel
     */
    public TaskModelEvent(Object source) {
        super(source);
    }

    /**
     * Use with ITaskModelListener.changeFeedbackCursor().  Affects all views.
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, Cursor cursor) {
        super(source);
        setCursor(cursor);
    }

    /**
     * Use with ITaskModelListener.changeFeedbackCursor().  Affects specified view.
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            Cursor cursor) {
        super(source);
        setViewInstance(viewInstance);
        setCursor(cursor);
    }

    /**
     * Use with ITaskModelListener.removeStatusItem().
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            IStatusItem item) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItem(item);
    }

    /**
     * Use with ITaskModelListener.addStatusItem().
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            IStatusItem item, String position) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItem(item);
        setStatusItemPosition(position);
    }

    /**
     * Use with ITaskModelListener.changeStatusItemState().
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            String statusItemID, Object statusItemState) {
        super(source);
        setViewInstance(viewInstance);
        setStatusItemState(statusItemID, statusItemState);
    }

    /**
     * Use with ITaskModelListener.enable/disableMenuItem().
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            String menuID) {
        super(source);
        setViewInstance(viewInstance);
        setMenuID(menuID);
    }

    /**
     * Use with ITaskModelListener.add/removeMenuItems().
     * Called by TaskModel
     */
    public TaskModelEvent(Object source, IPage viewInstance,
            IMenuInfo menuInfo) {
        super(source);
        setViewInstance(viewInstance);
        setMenuInfo(menuInfo);
    }

    /**
     * Returns view instance that this event is intended for.
     * Called by receiver of this event, an ITaskModelListener such as TaskPage.
     */
    public IPage getViewInstance() {
        return _viewInstance;
    }

    /**
     * Sets the view instance this event is intended for.
     * What is a viewInstance and why is it necessary?
     * A view instance is a unique identifier that represents a
     * page view.  Since an event is typically sent in response to a
     * change in the view, you will want to target an event only
     * to that view.  If an event applies to all views, the viewInstance
     * can be set to null.
     * Called by TaskModel
     */
    public void setViewInstance(IPage viewInstance) {
        _viewInstance = viewInstance;
    }


    /**
     * Returns a menu identifier.
     * Called by listener when processing enable/disableMenuItem()
     */
    public String getMenuID() {
        return _menuID;
    }

    /**
     * Sets menu item identifier.
     * Called by TaskModel
     */
    public void setMenuID(String menuID) {
        _menuID = menuID;
    }

    /**
     * Returns a menu information object.
     * Called by listener for add/removeMenuItems()
     */
    public IMenuInfo getMenuInfo() {
        return _menuInfo;
    }

    /**
     * Sets menu item object.
     * Called by TaskModel
     */
    public void setMenuInfo(IMenuInfo menuInfo) {
        _menuInfo = menuInfo;
    }

    /**
     * Sets status info object.
     * Called by TaskModel
     */
    public void setStatusItem(IStatusItem item) {
        _statusItem = item;
    }

    /**
     * Sets the state for a status item.
     * Called by TaskModel
     */
    public void setStatusItemState(String itemID, Object state) {
        _statusItemID = itemID;
        _statusItemState = state;
    }

    /**
     * Sets status item position
     * Called by TaskModel
     */
    public void setStatusItemPosition(String position) {
        _statusItemPosition = position;
    }

    /**
     * Returns the state for a status item.
     * Called by listener while processing addStatusItem()
     */
    public String getStatusItemPosition() {
        return _statusItemPosition;
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
     * Returns status bar text.
     * Called by listener while processing statusItemStateChanged(), statusItemAdded(), statusItemDeleted()
     */
    public IStatusItem getStatusItem() {
        return _statusItem;
    }

    /**
     * Returns cursor.
     * Called by listener while processing cursorChanged()
     */
    public Cursor getCursor() {
        return _cursor;
    }

    /**
     * Sets cursor.
     * Called by TaskModel
     */
    public void setCursor(Cursor cursor) {
        _cursor = cursor;
    }
}

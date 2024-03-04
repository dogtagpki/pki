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

/**
 * The interface that is notified of events eminating from ResourceModel.
 * This object requires registration with ResourceModel.
 *
 * @see ResourceModel#addIResourceModelListener
 * @see ResourceModelEvent
 */
public interface IResourceModelListener extends EventListener {
    /**
      * Adds one or more menu items to Console window menu bar
      *
      * @param e		a ResourceModelEvent containing details about menu item(s)
      */
    public abstract void addMenuItems(ResourceModelEvent e);

    /**
     * Removes one or more menu items from Console window menu bar
     *
     * @param e		a ResourceModelEvent containing details about menu item(s)
     */
    public abstract void removeMenuItems(ResourceModelEvent e);

    /**
     * Enables a menu item in Console window menu bar
     *
     * @param e		a ResourceModelEvent containing details about menu item(s)
     */
    public abstract void enableMenuItem(ResourceModelEvent e);

    /**
     * Disables a menu item in Console window menu bar
     *
     * @param e		a ResourceModelEvent containing details about menu item(s)
     */
    public abstract void disableMenuItem(ResourceModelEvent e);

    /**
     * Adds a status item to Console window status bar
     *
     * @param e		a ResourceModelEvent containing details about status item
     */
    public abstract void addStatusItem(ResourceModelEvent e);

    /**
     * Removes a status item from Console window status bar
     *
     * @param e		a ResourceModelEvent containing details about status item
     */
    public abstract void removeStatusItem(ResourceModelEvent e);

    /**
     * Changes state of status item to Console window status bar
     *
     * @param e		a ResourceModelEvent containing details about status item
     */
    public abstract void changeStatusItemState(ResourceModelEvent e);

    /**
     * Changes shape of mouse cursor in Console window
     *
     * @param e		a ResourceModelEvent containing details about cursor shape
     */
    public abstract void changeFeedbackCursor(ResourceModelEvent e);

    /**
     * Changes shape of mouse cursor in Console window
     *
     * @param e		a ResourceModelEvent containing details about cursor shape
     */
    public abstract void changeCustomPanel(ResourceModelEvent e);

    /**
     * Selects particular tree node(s) in ResourcePage of Console window
     *
     * @param e		a ResourceModelEvent specifying which nodes are to be selected
     */
    public abstract void selectTreeNode(ResourceModelEvent e);

    /**
     * Expands particular tree node(s) in ResourcePage of Console window
     *
     * @param e		a ResourceModelEvent specifying which nodes are to be expanded
     */
    public abstract void expandTreeNode(ResourceModelEvent e);
}

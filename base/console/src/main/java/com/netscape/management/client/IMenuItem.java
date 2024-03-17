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
import java.awt.event.*;

/**
 * Defines the minimum set of properties for a menu item
 * to be used with the IMenuInfo interface. Several
 * common types of menus have been implemented.
 *
 * @see IMenuItemText
 * @see IMenuItemCheckbox
 * @see IMenuItemCategory
 * @see IMenuItemSeparator
 */
public interface IMenuItem {
    /**
      * Returns identifer for this item, not
      * to be confused with the menu text or description
      * which are displayed in the UI.  The identifier
      * is used internally for tracking and reference purposes.
      *
      * @return a string ID
      */
    public abstract String getID();

    /**
        * A Component to render UI for this object.
        *
        * @return Component that renders UI for this object.
        */
    abstract Component getComponent();

    /**
        * Adds an ActionListener that gets called when a menu item
        * is selected.  There is an alternative way to detect
        * menu item selection, through the IMenuInfo.actionMenuSelected
        * method.
        *
        * @param actionListener	the ActionListener object
        * @see IMenuInfo.actionMenuSelected
        */
    abstract void addActionListener(ActionListener actionListener);

    /**
     * Removes an ActionListener that receives selection notification.
     *
     * @param actionListener	previously added ActionListener object
     */
    abstract void removeActionListener(ActionListener actionListener);
}

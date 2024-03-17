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

import java.awt.Cursor;

import javax.swing.JFrame;

/**
  * Interface to access properties and functions of Console window
  *
  * @see Framework
  */
public interface IFramework {
    /**
      * Returns the tab object that is currently selected in Console window
      *
      * @return an IPage object at the specified index
      */
    public abstract IPage getSelectedPage();

    /**
     * Returns title for Console window
     *
     * @return the string representing Console window
     */
    public abstract String getTitle();

    /**
     * Registers string to be used as title for Console window
     *
     * @param title		the string representing the title
     */
    public abstract void setTitle(String title);

    /**
     * Adds a status item to Console window status bar
     *
     * @param item		an IStatusItem object
     * @param position  a string constant defined in IStatusItem specifying
     *					position for this status item
     */
    public abstract void addStatusItem(IStatusItem item, String position);

    /**
     * Removes a status item from Console window status bar
     *
     * @param item		an IStatusItem object representing a status item
     */
    public abstract void removeStatusItem(IStatusItem item);

    /**
     * Changes state of a status item already on the status bar.
     *
     * @param itemID	a string identifier representing an IStatusItem
     *					that already exists in status bar
     * @param state		an object representing the new state for the status item
     */
    public abstract void changeStatusItemState(String itemID, Object state);

    /**
     * Adds menu item to Console window menu bar
     *
     * @param categoryID	a string identifier representing an existing menu
     *						category to which this menu item should be added
     * @param item			an IMenuItem object representing a menu item
     * @see IMenuItemCategory for a list of predefined meny categories
     */
    public abstract void addMenuItem(String categoryID, IMenuItem item);

    /**
     * Removes menu item from Console window menu bar
     *
     * @param item			an IMenuItem object representing a menu item
     */
    public abstract boolean removeMenuItem(IMenuItem item);

    /**
     * Sets shape of mouse cursor on Console window
     *
     * @param cursor	a Cursor object representing shape of mouse cursor
     * @deprecated		as of Console 4.1, replaced by Framework.setBusyCursor
     * @see	Framework#setBusyCursor(Cursor)
     */
    @Deprecated
    public abstract void setCursor(Cursor cursor);

    /**
     * Returns the current mouse cursor shape used by Console window
     *
     * @return a Cursor object representing shape of mouse cursor
     */
    public abstract Cursor getCursor();

    /**
     * Returns JFC JFrame object that displays Console window
     *
     * @return a JFrame object
     */
    public abstract JFrame getJFrame();
}

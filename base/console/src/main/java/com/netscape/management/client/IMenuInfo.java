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

/**
  * Allows a convenient way to define menu items and receive
  * menu notifications.  This interface can be implemented on
  * the following classes:
  * ResourceModel, ResourceObject, TaskModel, TaskObject.
  *
  * Another benefit of using this method to define menus is that
  * they are automatically added or  removed to the menu bar
  * as a tab page or object is selected or deselected.
  *
  * The sequence of method calls is as follows:
  * When a page or object implementing IMenuInfo is selected,
  * the getMenuCategoryIDs method is called.
  * This method returns one or more menu categories
  * that need menu items defined.  A menu category is either
  * a top level menu (Console, Edit, View, Object, Help)
  * or a cascading menu (Help->Web Based Help)
  *
  * Next, the getMenuItems method is called once for each category.
  * This method returns one or more menu items which
  * are then added to that menu category.
  *
  * @see IMenuItem
  * @see Framework
  * @see ResourcePage
  * @see TaskPage
  * @see ResourceObject
  * @see TaskObject
  */
public interface IMenuInfo {
    /**
       * Returns one or more menu categories which need menu definations.
       * Predefined menu categories (Console, Edit, View, etc) are
       * defined in Framework, ResourcePage, and TaskPage as
       * static string constants with the MENU_ prefix.
       *
       * @return an array of strings representing menu categories
       */
    public abstract String[] getMenuCategoryIDs();

    /**
      * Returns one or more menu items which are added to the
      * specified menu category.  The order in which the menu
      * items are appear in the menu category is determined
      * by Console.  For example, if you add a menu item to
      * the "Console" menu, it will appear after the first
      * menu item (varies per tab) and before the last (Exit).
      *
      * @return an array of IMenuItem objects.
      * @see MenuItemText
      * @see MenuItemCheckbox
      * @see MenuItemCategory
      * @see MenuItemSeparator
      */
    public abstract IMenuItem[] getMenuItems(String category);

    /**
      * Called as a notification when a menu item is selected.
      * Only menu items populated through this class instance
      * are notified here.  That is, you will not receive
      * notifications for File -> Exit, for example.
      *
      * @param viewInstance an IPage object representing the instance of
      *                     the tab in which this menu was selected.
      * @param item			the IMenuItem object that was selected.
      */
    public abstract void actionMenuSelected(IPage viewInstance,
            IMenuItem item);
}

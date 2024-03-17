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
import java.awt.event.*;
import javax.swing.*;

/**
  * Utility class to group menu information.
  * Used by TaskPage and ResourcePage
  */
class MenuData {
    String _categoryID = null;
    IMenuItem _item = null;
    IMenuInfo _menuInfo = null;

    MenuData(String categoryID, IMenuItem menuItem, IMenuInfo menuInfo) {
        setCategoryID(categoryID);
        setIMenuItem(menuItem);
        setIMenuInfo(menuInfo);
    }

    String getCategoryID() {
        return _categoryID;
    }

    IMenuItem getIMenuItem() {
        return _item;
    }

    IMenuInfo getIMenuInfo() {
        return _menuInfo;
    }

    void setCategoryID(String categoryID) {
        _categoryID = categoryID;
    }

    void setIMenuItem(IMenuItem item) {
        _item = item;
    }

    void setIMenuInfo(IMenuInfo menuInfo) {
        _menuInfo = menuInfo;
    }

    public static Vector createMenuData(IMenuInfo menuInfo,
            ActionListener actionListener) {
        Vector menuData = new Vector();
        String categoryID[] = menuInfo.getMenuCategoryIDs();
        if (categoryID != null) {
            for (int index = 0; index < categoryID.length; index++) {
                IMenuItem menuItem[] =
                        menuInfo.getMenuItems(categoryID[index]);
                if (menuItem != null) {
                    for (int menuIndex = 0;
                            menuIndex < menuItem.length; menuIndex++) {
                        if (actionListener != null) {
                            menuItem[menuIndex].removeActionListener(
                                    actionListener);
                            menuItem[menuIndex].addActionListener(
                                    actionListener);
                        }
                        menuData.addElement( new MenuData(categoryID[index],
                                menuItem[menuIndex], menuInfo));
                    }
                }
            }
        }
        return menuData;
    }

    public static IMenuItem findIMenuItem(Vector menuDataVector,
            String menuID) {
        Enumeration e = menuDataVector.elements();
        while (e.hasMoreElements()) {
            MenuData menuData = (MenuData) e.nextElement();
            if (menuID.equals(menuData.getIMenuItem().getID())) {
                return menuData.getIMenuItem();
            }
        }
        return null;
    }

    public static IMenuInfo findIMenuInfo(Vector menuDataVector,
            IMenuItem menuItem) {
        Enumeration e = menuDataVector.elements();
        while (e.hasMoreElements()) {
            MenuData menuData = (MenuData) e.nextElement();
            if (menuItem == menuData.getIMenuItem()) {
                return menuData.getIMenuInfo();
            }
        }
        return null;
    }

    public static void enableMenuItem(Vector menuDataVector,
            String menuID, boolean state) {
        Enumeration e = menuDataVector.elements();
        while (e.hasMoreElements()) {
            MenuData menuData = (MenuData) e.nextElement();
            if (menuID.equals(menuData.getIMenuItem().getID())) {
                IMenuItem menuItem = menuData.getIMenuItem();
                if (menuItem.getComponent() instanceof AbstractButton) {
                    AbstractButton button =
                            (AbstractButton) menuItem.getComponent();
                    button.setEnabled(state);
                }
            }
        }
    }

    public static void addVectors(Vector v1, Vector v2) {
        Enumeration e = v2.elements();
        while (e.hasMoreElements()) {
            v1.addElement(e.nextElement());
        }
    }

    public static Vector createMenuDataByID(Vector v1, Vector v2) {
        Vector v = new Vector();
        Enumeration e2 = v2.elements();
        while (e2.hasMoreElements()) {
            MenuData menuDataToRemove = (MenuData) e2.nextElement();
            Enumeration e1 = v1.elements();
            while (e1.hasMoreElements()) {
                MenuData menuData = (MenuData) e1.nextElement();
                if ((menuData.getIMenuItem().getID().equals(
                        menuDataToRemove.getIMenuItem().getID())) &&
                        (menuData.getCategoryID().equals(
                        menuDataToRemove.getCategoryID()))) {
                    v.addElement(menuData);
                    break;
                }
            }
        }
        return v;
    }

    public static void substractVectors(Vector v1, Vector v2) {
        Enumeration e = v2.elements();
        while (e.hasMoreElements()) {
            v1.removeElement(e.nextElement());
        }
    }


    /**
     * Returns a JFC menu item for a specified menu category.
     */
    public static JMenu getMenu(JPopupMenu popupMenu, String categoryID) {
        JMenu result = null;
        for (int index = 0; index < popupMenu.getComponentCount();
                index++) {
            Component menu = popupMenu.getComponentAtIndex(index);
            if ((menu instanceof IMenuItemCategory) && (categoryID.equals(
                    ((IMenuItemCategory) menu).getID()))) {
                result = (JMenu)((IMenuItemCategory) menu).getComponent();
                break;
            } else if (menu instanceof JMenu) {
                JMenu newResult =
                        MenuData.getMenu((JMenu) menu, categoryID);
                if (newResult != null) {
                    result = newResult;
                    break;
                }
            }
        }
        return result;
    }


    /**
     * Returns JFC menu item for a specified menu category.
     * See IMenuCategory for predefined menu categories.
     */
    public static JMenu getMenu(JMenu parent, String categoryID) {
        JMenu result = null;
        for (int index = 0; index < parent.getMenuComponentCount();
                index++) {
            Component c = parent.getMenuComponent(index);
            if ((c instanceof IMenuItemCategory) &&
                    (categoryID.equals(((IMenuItemCategory) c).getID()))) {
                result = (JMenu)((IMenuItemCategory) c).getComponent();
                break;
            } else if (c instanceof JMenu) {
                JMenu newResult = getMenu((JMenu) c, categoryID);
                if (newResult != null) {
                    result = newResult;
                    break;
                }
            }
        }
        return result;
    }

    /**
       * Returns a JFC menu item for a specified menu category.
       */
    public static JMenu getMenu(JMenuBar menuBar, String categoryID) {
        JMenu result = null;
        for (int index = 0; index < menuBar.getMenuCount(); index++) {
            JMenu menu = menuBar.getMenu(index);
            if ((menu instanceof IMenuItemCategory) && (categoryID.equals(
                    ((IMenuItemCategory) menu).getID()))) {
                result = (JMenu)((IMenuItemCategory) menu).getComponent();
                break;
            } else if (menu instanceof JMenu) {
                JMenu newResult = MenuData.getMenu(menu, categoryID);
                if (newResult != null) {
                    result = newResult;
                    break;
                }
            }
        }
        return result;
    }


    public static boolean removeMenuItem(JMenu parent, IMenuItem item) {
        boolean result = false;
        for (int index = 0; index < parent.getMenuComponentCount();
                index++) {
            Component c = parent.getMenuComponent(index);
            if ((c instanceof IMenuItem) && (c == item)) {
                parent.remove(index);
                result = true;
                break;
            } else if (c instanceof JMenu) {
                if (removeMenuItem((JMenu) c, item) == true) {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }


}

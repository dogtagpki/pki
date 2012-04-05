// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv;

import javax.swing.*;
import javax.swing.tree.*;
import javax.swing.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import java.util.*;

/**
 * This class represents the menu item selection and associated
 * call back function.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class CMSBaseMenuInfo implements IMenuInfo {

    /*==========================================================
     * variables
     *==========================================================*/
    //framework level menu catagory ids
    public static String MENU_FILE = Framework.MENU_FILE;
    public static String MENU_VIEW = Framework.MENU_VIEW;
    public static String MENU_OBJECT = ResourcePage.MENU_OBJECT;

    //menu bar menu items
    public static String MENU_KEYCERT = CMSAdminResources.MENU_KEYCERT;
    public static String MENU_REFRESH = CMSAdminResources.MENU_REFRESH;
    public static String MENU_KEYCERT_MANAGEMENT = CMSAdminResources.MENU_KEYCERT_MANAGEMENT;
    public static String MENU_PKCS11 = CMSAdminResources.MENU_PKCS11;
    public static String MENU_NEWCERT = CMSAdminResources.MENU_NEWCERT;

    //context menu items


    protected Vector mMenuCategoryIDs;      //stores the ids
    protected Vector mCategoryIDMenuItems;  //stores the menu items associated
                                            //with the specified id
    protected Vector mMenuItemsIDs;         //stores the item ids
    protected Vector mActionListeners;      //stores the action listeners

    protected ResourceBundle mResource;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseMenuInfo() {
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mMenuCategoryIDs = new Vector();
        mCategoryIDMenuItems = new Vector();
        mMenuItemsIDs = new Vector();
        mActionListeners = new Vector();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Register menu items and associated action obejct
     * @param id menu catagory ID
     * @param item menu item
     * @param action IMenuAction object
     */
    public void registerMenuItem(String id, String keyword, IMenuAction action) {
        IMenuItem item = getMenuItemText(keyword);

        //register menu item and action pair
        int i = mMenuItemsIDs.indexOf(item.getID());
        if (i == -1) {
            mMenuItemsIDs.addElement(item.getID());
            mActionListeners.addElement(action);
        } else {
            mActionListeners.setElementAt(action,i);
        }

        //register catgory id and associated menu items
        i = mMenuCategoryIDs.indexOf(id);
        if (i == -1) {
            mMenuCategoryIDs.addElement(id);
            mCategoryIDMenuItems.addElement(new Vector());
        }
        i = mMenuCategoryIDs.indexOf(id);
        Vector items = (Vector) mCategoryIDMenuItems.elementAt(i);
        items.addElement(item);     //XXX check exist already ??
    }

    /**
     * Add menu item separator
     */
    public void addMenuItemSeparator(String id) {
        int i = mMenuCategoryIDs.indexOf(id);
        if (i < 0 ) {
            mMenuCategoryIDs.addElement(id);
            Vector items = new Vector();
            items.addElement(new MenuItemSeparator());
            mCategoryIDMenuItems.addElement(items);
        } else {
            Vector items = (Vector) mCategoryIDMenuItems.elementAt(i);
            items.addElement(new MenuItemSeparator());
        }
    }

    /**
      * Returns supported menu categories.
      */
	public String[] getMenuCategoryIDs() {
	    if (mMenuCategoryIDs.size() == 0) {
	        return null;
	    }
        String[] id = new String[mMenuCategoryIDs.size()];
        mMenuCategoryIDs.copyInto(id);
        //for(int i=0; i< id.length; i++)
        //    System.out.println("ID: "+id[i]);
        return id;
    }

    /**
      * Returns menu items for a particular menu category.
      */
	public IMenuItem[] getMenuItems(String category) {
        int i = mMenuCategoryIDs.indexOf(category);
        if (i != -1) {
            Vector v = (Vector) mCategoryIDMenuItems.elementAt(i);
            IMenuItem[] items = new IMenuItem[v.size()];
            v.copyInto(items);
            //for(int j=0; j< items.length; j++)
            //    System.out.println("ITEM: "+items[j].getID());
            return items;
        }
        return null;
	}

    /**
      * Notification that a menu item has been selected.
      */
	public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        int i = mMenuItemsIDs.indexOf(item.getID());
        if (i == -1)
            return;
        IMenuAction act = (IMenuAction) mActionListeners.elementAt(i);
        act.perform(viewInstance);
	}

    /*==========================================================
	 * priotected methods
     *==========================================================*/

    protected MenuItemText getMenuItemText(String keyword) {
        String name = mResource.getString("GENERAL_MENU_"+keyword+"_LABEL");
        if (name == null)
            name = "Missing Label";
        String desc = mResource.getString("GENERAL_MENU_"+keyword+"_DESC");
        if (desc == null)
            desc = " ";
        return new MenuItemText( keyword, name, desc);
    }

}

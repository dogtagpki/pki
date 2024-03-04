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
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.UITools;

/**
  * Implements a menu category, which may be a top-level menu,
  * or a cascading menu.  Predefined categories include:
  *
  * Framework.MENU_TOP			Use to add top level menu in a Console window
  * Framework.MENU_FILE			Use to add to "Console" menu in a Console window
  * Framework.MENU_EDIT			Use to add to "Edit" menu in a Console window
  * Framework.MENU_VIEW			Use to add to "View" menu in a Console window
  * Framework.MENU_HELP			Use to add to "Help" menu in a Console window
  * Framework.MENU_HELPWEBHELP	Use to add to "Help"->"Web-Based Resources" menu in a Console window
  * ResourcePage.MENU_CONTEXT	Use to add to context (popup) menu in a ResourcePage
  * TaskPage.MENU_CONTEXT		Use to add to context (popup) menu in a TaskPage
  *
  * @see IMenuItemCategory
  */
public class MenuItemCategory extends JMenu implements IMenuItemCategory {
    String _id = null;
    String _description = null;

    /**
     * Constructs menu item object and sets its ID and label.
     *
        * @param id			string identifier for this menu item
        * @param label			string to display on menu item
     */
    public MenuItemCategory(String id, String label) {
        this(id, label, true);
    }

    /**
      * Constructs menu item object and sets its ID, label and description.
      *
         * @param id			string identifier for this menu item
         * @param label			string to display on menu item
         * @param enabled		boolean specifying initial enabled state
      */
    public MenuItemCategory(String id, String label, boolean enabled) {
        setID(id);
        setText(UITools.getDisplayLabel(label));
        setMnemonic(UITools.getMnemonic(label));
        setEnabled(enabled);
    }

    /**
       * Registers the text to display on the menu item.
       * This string should be internationalized and
       * may contain a keyboard shortcut if applicable.
       * It is defined by using an ampersand (&) character.
       * For example, "&View" defines alt-V as the
       * shortcut keystroke.
       *
       * @param label	the string to display on this menu item
       */
    public void setText(String label) {
        super.setText(UITools.getDisplayLabel(label));
    }

    /**
         * A Component to render UI for this object.
         *
         * @return Component that renders UI for this object.
         */
    public Component getComponent() {
        return this;
    }

    /**
      * Returns identifer for this item, not
      * to be confused with the menu text or description
      * which are displayed in the UI.  The identifier
      * is used internally for tracking and reference purposes.
      *
      * @return string identifier
      */
    public String getID() {
        return _id;
    }

    /**
      * Sets identifer for this item, not
      * to be confused with the menu text or description
      * which are displayed in the UI.  The identifier
      * is used internally for tracking and reference purposes.
      *
      * @param id	string identifier
      */
    public void setID(String id) {
        _id = id;
    }

    /**
      * Defines the text to display on the status bar as
      * this menu item is being selected.
      *
      * @return the string to display
      */
    public String getDescription() {
        return _description;
    }

    /**
      * Sets text to display on status bar as
      * menu item is being selected.
      *
      * @param description the description string
      */
    public void setDescription(String description) {
        _description = description;
    }

    /**
      * Convenience method for adding separator to this
      * menu category.
      */
    public void addSeparator() {
        IMenuItemSeparator item = new MenuItemSeparator();
        add(item.getComponent());
    }

    /**
       * Inserts menu item to this category.
       * This method overrides JMenu.insert() because that is broken.
       */
    public Component insert(Component c, int position) {
        Vector v = new Vector();

        // all this because there is no insert(Component, pos) in JMenu
        for (int index = 0; index < getMenuComponentCount(); index++)
            v.addElement(getMenuComponent(index));

        removeAll();

        v.insertElementAt(c, position);

        for (Enumeration e = v.elements(); e.hasMoreElements();) {
            add((Component) e.nextElement());
        }
        return c;
    }
}

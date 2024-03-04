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

import java.awt.Component;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import com.netscape.management.client.util.UITools;

/**
 * Implements a standard text menu item.
 *
 * @IMenuItemText
 */
public class MenuItemText extends JMenuItem implements IMenuItemText {
    String _id = null;
    String _description = null;

    /**
     * Constructs a text menu item object, and sets its text and description.
     * The ID is not set.
     *
        * @param label			string to display on menu item
        * @param description   string to display on status bar as menu is being selected
        * @deprecated	use #MenuItemText(String, String, String)
     */
    @Deprecated
    public MenuItemText(String label, String description) {
        this("<noID>", label, description);
    }

    /**
      * Constructs a text menu item object, and sets its text,
      * description, and an enabled flag that determines whether
      * the menu should be initially grayed out.
      * The ID is not set.
      *
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param enabled		boolean specifying initial enabled state
         * @deprecated	use #MenuItemText(String, String, String, boolean)
      */
    @Deprecated
    public MenuItemText(String label, String description, boolean enabled) {
        this("<noID>", label, description, enabled);
    }

    /**
      * Constructs a text menu item object, and sets its text,
      * description, and a listener receives notifications when
      * the menu is selected.
      * The ID is not set.
      *
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param actionListener ActionListener that receives notifications after menu is selected
         * @deprecated	use #MenuItemText(String, String, String, ActionListener)
      */
    @Deprecated
    public MenuItemText(String label, String description,
            ActionListener actionListener) {
        this(label, description);
        addActionListener(actionListener);
    }

    /**
      * Constructs a text menu item object, and sets its ID, text,
      * and description.
      *
         * @param id			string identifier for this menu item
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
      */
    public MenuItemText(String id, String label, String description) {
        this(id, label, description, true);
    }

    /**
      * Constructs a text menu item object, and sets its ID, text,
      * description, and an enabled flag that determines whether
      * the menu should be initially grayed out.
      *
         * @param id			string identifier for this menu item
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param enabled		boolean specifying initial enabled state
      */
    public MenuItemText(String id, String label, String description,
            boolean enabled) {
        setID(id);
        setText(UITools.getDisplayLabel(label));
        setMnemonic(UITools.getMnemonic(label));
        setDescription(description);
        setEnabled(enabled);
    }

    /**
      * Constructs a text menu item object, and sets its ID, text,
      * description, and a listener receives notifications when
      * the menu is selected.
      *
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param actionListener ActionListener that receives notifications after menu is selected
      */
    public MenuItemText(String id, String label, String description,
            ActionListener actionListener) {
        this(id, label, description);
        addActionListener(actionListener);
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
      * Sets identifer for this item, not to be confused
      * with the menu text or description (which are displayed in the UI.)
      * The identifier is used internally for tracking and reference purposes.
      *
      * @return string identifier
      */
    public String getID() {
        return _id;
    }

    /**
      * Sets identifer for this item, not to be confused
      * with the menu text or description (which are displayed in the UI.)
      * The identifier is used internally for tracking and reference purposes.
      *
      * @param id	string identifier
      */
    public void setID(String id) {
        _id = id;
    }

    /**
      * Returns text to display on status bar as menu item is being selected.
      *
      * @return string display on status bar as menu is being selected
      */
    public String getDescription() {
        return _description;
    }

    /**
      * Sets text to display on status bar as menu item is being selected.
      *
      * @param description	string to display on status bar as menu is being selected
      */
    public void setDescription(String description) {
        _description = description;
    }
}

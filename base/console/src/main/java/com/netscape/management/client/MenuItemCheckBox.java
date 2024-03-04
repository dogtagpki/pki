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
import javax.swing.*;
import com.netscape.management.client.util.UITools;

/**
  * Implements a toggle menu item.
  * Selecting it toggles its checked state.
  *
  * @IMenuItemCheckBox
  */
public class MenuItemCheckBox extends JCheckBoxMenuItem implements IMenuItemCheckBox {
    String _id = null;
    String _description = null;

    /**
     * Constructs a text menu item object, and sets its text,
     * description, and an enabled flag that determines whether
     * the menu should be initially grayed out.
     * The ID is not set.
     *
        * @param label			string to display on menu item
        * @param description   string to display on status bar as menu is being selected
        * @param enabled		boolean specifying initial enabled state
     */
    public MenuItemCheckBox(String label, String description,
            boolean state) {
        this("<noID>", label, description, state);
    }

    /**
      * Constructs a text menu item object, and sets its ID, text,
      * description, and a checked flag that determines whether
      * the menu should be initially checked.
      *
         * @param id			string identifier for this menu item
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param checked		boolean specifying initial checked state
      */
    public MenuItemCheckBox(String id, String label,
            String description, boolean checked) {
        setID(id);
        setText(UITools.getDisplayLabel(label));
        setMnemonic(UITools.getMnemonic(label));
        setDescription(description);
        setChecked(checked);
    }

    /**
      * Constructs a text menu item object, and sets its ID, text,
      * description, and a checked flag that determines whether
      * the menu should be initially checked out.
      *
         * @param id			string identifier for this menu item
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param checked		boolean specifying initial checked state
      */
    public MenuItemCheckBox(String id, String label,
            String description, ActionListener actionListener,
            boolean checked) {
        this(id, label, description, checked);
        addActionListener(actionListener);
    }

    /**
      * Constructs a menu item object, and sets its text,
      * description, and a listener receives notifications when
      * the menu is selected, and a checked flag that determines
      * whether the menu should be initially grayed out.
      *
         * @param label			string to display on menu item
         * @param description   string to display on status bar as menu is being selected
         * @param actionListener ActionListener that receives notifications after menu is selected
         * @param checked		boolean specifying initial enabled state
      */
    public MenuItemCheckBox(String label, String description,
            ActionListener actionListener, boolean checked) {
        this(label, description, checked);
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
      * Returns text to display on status bar as menu item is being selected.
      *
      * @return string to display on status bar as menu is being selected
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

    /**
      * Returns menu item checked state
      *
      * @return boolean checked state
      */
    public boolean isChecked() {
        return isSelected();
    }

    /**
      * Sets menu item checked state
      *
      * @param checked		boolean specifying checked state for menu item
      */
    public void setChecked(boolean checked) {
        setSelected(checked);
    }
}

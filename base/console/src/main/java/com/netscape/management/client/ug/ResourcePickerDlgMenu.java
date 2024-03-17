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

package com.netscape.management.client.ug;

import java.awt.event.*;

import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

/**
 * This class will create a set of menu items for the Resource Picker Dialog.
 *
 * @author  <a href=mailto:terencek@netscape.com>Terence Kwan</a>
 * @version 0.2 9/3/97
 */

public class ResourcePickerDlgMenu extends JMenuBar {

    JMenuItem createMenuItem(JMenu jmenu, String s,
            ActionListener listener, String command) {
        JMenuItem menuItem = jmenu.add(new JMenuItem(s));
        menuItem.addActionListener(listener);
        menuItem.setActionCommand(command);
        return menuItem;
    }

    JMenuItem insertMenuItem(JMenu jmenu, String s,
            ActionListener listener, String command, int index) {
        JMenuItem menuItem = jmenu.insert(new JMenuItem(s), index);
        menuItem.addActionListener(listener);
        menuItem.setActionCommand(command);
        return menuItem;
    }

    public void addSearchInterfaceMenuItem(String display, String ID,
            int index) {
        insertMenuItem(_mView, display, parent, "SHOW:"+ID, index);
    }

    public void deleteSearchInterfaceMenuItem(int index) {
        _mView.remove(index);
    }

    public void disableSearchInterfaceMenuItem(int index, boolean fEnable) {
        (_mView.getItem(index)).setEnabled(fEnable);
    }

    ActionListener parent;
    JMenu _mFile, _mEdit, _mView, _mHelp;

    public ResourcePickerDlgMenu(ActionListener parent) {
        super();
        setSize(500, 23);

        this.parent = parent;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();

        _mFile = (JMenu) add(
                new JMenu(resource.getString("resourcePicker", "menuItemFile")));
        _mEdit = (JMenu) add(
                new JMenu(resource.getString("resourcePicker", "menuItemEdit")));
        _mView = (JMenu) add(
                new JMenu(resource.getString("resourcePicker", "menuItemView")));
        _mHelp = (JMenu) add(
                new JMenu(resource.getString("resourcePicker", "menuItemHelp")));


        int nItems = Integer.parseInt(
                resource.getString("resourcePicker", "NmenuItemFile"));
        for (int i = 0; i < nItems; i++) {
            createMenuItem(_mFile,
                    resource.getString("resourcePicker",
                    "menuItemFile"+i), parent,
                    resource.getString("resourcePicker", "menuItemFileCommand"+i));
        }

        nItems =
                Integer.parseInt(resource.getString("resourcePicker", "NmenuItemEdit"));
        for (int i = 0; i < nItems; i++) {
            String item = resource.getString("resourcePicker", "menuItemEdit"+i);
            if (item.equals("SEPARATOR")) {
                _mEdit.addSeparator();
            } else {
                createMenuItem(_mEdit, item, parent,
                        resource.getString("resourcePicker", "menuItemEditCommand"+i));
            }
        }

        nItems =
                Integer.parseInt(resource.getString("resourcePicker", "NmenuItemView"));
        for (int i = 0; i < nItems; i++) {
            String item = resource.getString("resourcePicker", "menuItemView"+i);
            if (item.equals("SEPARATOR")) {
                _mView.addSeparator();
            } else {
                createMenuItem(_mView, item, parent,
                        resource.getString("resourcePicker", "menuItemViewCommand"+i));
            }
        }

        createMenuItem(_mHelp,
                resource.getString("resourcePicker", "menuItemNetHelp0"),
                parent, resource.getString("resourcePicker", "menuItemNetHelpCommand0"));
    }

}



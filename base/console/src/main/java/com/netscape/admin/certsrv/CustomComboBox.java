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

import java.awt.Color;
import java.awt.Component;
import java.util.Hashtable;

import javax.swing.ComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

/**
 * General Purpose Custom Combo Box
 *
 * @author  jpanchen
 * @version $Revision$, $Date$
 * @see     com.netscape.admin.certsrv
 * @see     CustomComboBoxModel
 */
public class CustomComboBox<E> extends JComboBox<E> {

    public CustomComboBox(ComboBoxModel<E> m) {
        super(m);
        super.setRenderer( new CustomCellRenderer<>(this));
    }
}

class CustomCellRenderer<E> extends JLabel implements ListCellRenderer<E>   {

    final static Color selectedCellBackground = new Color(0,0,128);
    final static Color selectedCellForeground = Color.white;
    final static Color defaultCellBackground = Color.white;
    final static Color defaultCellForeground = Color.black;
    final static String SELECTION_TITLE = CustomComboBoxModel.SELECTION_TITLE;
    final static String SELECTION_ICON = CustomComboBoxModel.SELECTION_ICON;

    CustomComboBox<E> combobox;

    public CustomCellRenderer(CustomComboBox<E> x) {
        combobox = x;
        setOpaque(true);
    }

    @Override
    public Component getListCellRendererComponent(
        JList<? extends E> listbox, E value, int index,
        boolean isSelected, boolean cellHasFocus)
    {
        Hashtable<String, Object> h = (Hashtable<String, Object>) value;
        if(value == null) {
            setText("");
            setIcon(null);
            setBackground(selectedCellBackground);
	        setForeground(selectedCellForeground);
        } else {
            setIcon((ImageIcon)h.get(SELECTION_ICON));
            setText((String)h.get(SELECTION_TITLE));
            setBackground(defaultCellBackground);
	        setForeground(defaultCellForeground);
        }

    return this;
    }
}

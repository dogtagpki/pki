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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

/**
 * General Purpose Custom Combo Box
 *
 * @author  jpanchen
 * @version $Revision$, $Date$
 * @see     com.netscape.admin.certsrv
 * @see     CustomComboBoxModel
 */
public class CustomComboBox extends JComboBox {

    public CustomComboBox(ComboBoxModel m) {
        super(m);
        super.setRenderer( new CustomCellRenderer(this));
    }
}

class CustomCellRenderer extends JLabel implements ListCellRenderer   {
    
    final static Color selectedCellBackground = new Color(0,0,128);
    final static Color selectedCellForeground = Color.white;
    final static Color defaultCellBackground = Color.white;
    final static Color defaultCellForeground = Color.black;
    final static String SELECTION_TITLE = CustomComboBoxModel.SELECTION_TITLE;
    final static String SELECTION_ICON = CustomComboBoxModel.SELECTION_ICON;
    
    CustomComboBox combobox;

    public CustomCellRenderer(CustomComboBox x) {
        combobox = x;
        setOpaque(true);
    }

    public Component getListCellRendererComponent(
        JList listbox, Object value, int index,
        boolean isSelected, boolean cellHasFocus)
    {
        Hashtable h = (Hashtable) value;
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

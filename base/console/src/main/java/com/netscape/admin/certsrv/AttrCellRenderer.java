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

import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTextField;
import javax.swing.ListCellRenderer;
import javax.swing.border.EmptyBorder;

/**
 * class used to crate the label to be displayed in the attr list
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class AttrCellRenderer<E> extends JLabel implements ListCellRenderer<E> {
    static Color HIGHLIGHTCOLOR = new Color(0, 0, 128);
    static Color WHITECOLOR = Color.white;
    static Color BLACKCOLOR = Color.black;

    public AttrCellRenderer() {
        setOpaque(true);
        setBorder(new EmptyBorder(1,CMSAdminUtil.COMPONENT_SPACE, 1, 2));
        JTextField temp = new JTextField();
        setFont(temp.getFont());
    }

    @Override
    public Component getListCellRendererComponent(JList<? extends E> list,
        E value, int index, boolean isSelected, boolean cellHasFocus) {

        if (value instanceof JLabel) {
            setText(((JLabel)value).getText());
            setIcon(((JLabel)value).getIcon());
            setHorizontalAlignment(((JLabel)value).getHorizontalAlignment());
        } else {
            if (value instanceof String) {
                setText((String) value);
            } else {
                setText(value.toString());
            }
        }
        setBackground(isSelected ? HIGHLIGHTCOLOR : WHITECOLOR);
        setForeground(isSelected ? WHITECOLOR : BLACKCOLOR);
        return this;
    }
}
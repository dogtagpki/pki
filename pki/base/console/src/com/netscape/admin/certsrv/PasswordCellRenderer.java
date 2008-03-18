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
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

/**
 * class used to creat the password label
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class PasswordCellRenderer extends JLabel
    implements ListCellRenderer, TableCellRenderer
{
    static Color HIGHLIGHTCOLOR = new Color(0, 0, 128);
    static Color WHITECOLOR = Color.white;
    static Color BLACKCOLOR = Color.black;

    public PasswordCellRenderer() {
        super();
	    setOpaque(true);
        setBorder(new EmptyBorder(1,CMSAdminUtil.COMPONENT_SPACE, 1, 2));
        JPasswordField temp = new JPasswordField();
        setFont(temp.getFont());
    }

    public Component getListCellRendererComponent(JList list,
        Object value, int index, boolean isSelected, boolean cellHasFocus) {
        StringBuffer buf = new StringBuffer();
        for(int i=0; i< ((String)value).length(); i++)
            buf.append("*");
                setText(buf.toString());
        setBackground(isSelected ? HIGHLIGHTCOLOR : WHITECOLOR);
        setForeground(isSelected ? WHITECOLOR : BLACKCOLOR);
        return this;
    }

    public Component getTableCellRendererComponent(JTable table, Object value,
        boolean isSelected, boolean hasFocus, int row, int column) {
        if (value!=null) {
            StringBuffer buf = new StringBuffer();
            for(int i=0; i< ((String)value).length(); i++)
                buf.append("*");
                    setText(buf.toString());
            setBackground(isSelected ? HIGHLIGHTCOLOR : WHITECOLOR);
            setForeground(isSelected ? WHITECOLOR : BLACKCOLOR);
        }
        return this;

    }

}

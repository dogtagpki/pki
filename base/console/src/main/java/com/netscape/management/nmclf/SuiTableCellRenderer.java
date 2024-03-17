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
package com.netscape.management.nmclf;

import java.awt.*;
import javax.swing.*;
import javax.swing.table.*;
import com.netscape.management.client.util.*;

/**
 * Sets the correct insets
 * data to be highlighted.   JTable only highlights the
 * current cell, which is non-standard Windows UI behavior.
 *
 * @author ahakim@netscape.com
 */
public class SuiTableCellRenderer extends DefaultTableCellRenderer implements SuiConstants {

    public Component getTableCellRendererComponent(JTable table,
            Object value, boolean isSelected, boolean hasFocus,
            int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value != null && c instanceof JLabel) {
            JLabel l = (JLabel)c;
            l.setIcon(null);
            l.setBorder(BorderFactory.createEmptyBorder(VERT_COMPONENT_INSET, HORIZ_COMPONENT_INSET, VERT_COMPONENT_INSET, HORIZ_COMPONENT_INSET));
            if (value instanceof SuiIconText) {
                SuiIconText sit = (SuiIconText) value;
                l.setIcon(sit.getIcon());
                l.setText(sit.getText());
            } else if (value instanceof RemoteImage) {
                l.setIcon((RemoteImage) value);
                l.setText("");
            } else if (value instanceof JLabel) {
                JLabel vl = (JLabel) value;
                l.setIcon(vl.getIcon());
                l.setFont(vl.getFont());
                l.setText(vl.getText());
            }
        }
        return c;
    }
}

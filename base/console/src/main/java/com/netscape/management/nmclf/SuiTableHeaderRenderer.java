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

/**
 *	This class creates a table column header renderer component
 *  that aligns the text to the left and makes the column appear
 *  as a regular button.
 *
 *  This code sample uses the factory function createTableColumn().
 *  <code>
 *		JTable table = new JTable();
 *		table.addColumn(SuiTableHeaderRenderer.createTableColumn(0, "abc"));
 *		table.addColumn(SuiTableHeaderRenderer.createTableColumn(1, "def"));
 *		table.addColumn(SuiTableHeaderRenderer.createTableColumn(2, "ghi"));
 *  </code>
 * @author ahakim@netscape.com
 */
public class SuiTableHeaderRenderer extends JButton implements TableCellRenderer,
SwingConstants {
    public SuiTableHeaderRenderer() {
        setHorizontalAlignment(SwingConstants.LEFT);
        setHorizontalTextPosition(SwingConstants.LEFT);
        setBorder(new SuiTableHeaderBorder(SuiTableHeaderBorder.RAISED));
        setForeground(UIManager.getColor("textText"));
        setBackground(UIManager.getColor("control"));
        setOpaque(true);
    }

    /**
     * for TableCellRenderer, Swing 1.0
      */
    public Component getTableCellRendererComponent(JTable table,
            Object value, boolean isSelected, boolean something,
            int row, int column) {
        setText((String) value);
        return this;
    }
}

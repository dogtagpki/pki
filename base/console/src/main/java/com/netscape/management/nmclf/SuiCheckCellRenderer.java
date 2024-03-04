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
import javax.swing.border.*;
import javax.swing.table.*;

/**
 * Table renderer for checkboxes
 * Note: it attempts to set the right highlight colors, but they don't
 * ever change.
 *
 * @author  rweltman
 * @version %I%, %G%
 * @date	 	9/15/97
 * @see     com.netscape.admin.dirserv
 */

public class SuiCheckCellRenderer implements TableCellRenderer {
    private JCheckBox checkBox = new JCheckBox();
    private Border emptyBorder = new EmptyBorder(1,1,1,1);
    private Border focusBorder = new LineBorder(Color.lightGray,1);
    
    public JCheckBox getCheckBox()
    {
        return checkBox;
    }
    
    public Component getTableCellRendererComponent(
                                                   JTable table, 
                                                   Object value,
                                                   boolean isSelected, 
                                                   boolean hasFocus, 
                                                   int row, 
                                                   int column) {
        
        checkBox.setHorizontalAlignment(SwingConstants.CENTER);
        if ( value != null ) {
            checkBox.setSelected( ((Boolean)value).booleanValue() );
        } else
        {
            checkBox.setSelected(false);
        }
        if (hasFocus) {
            checkBox.setBorder(focusBorder);
        } else {
            checkBox.setBorder(emptyBorder);
        }
        if( isSelected ) {
            checkBox.setOpaque( true );
            checkBox.setForeground(table.getSelectionForeground());
            checkBox.setBackground(table.getSelectionBackground());
        } else {
            checkBox.setOpaque( false );
            checkBox.setForeground(table.getForeground());
            checkBox.setBackground(table.getBackground());
        }
        return checkBox;
    }
}

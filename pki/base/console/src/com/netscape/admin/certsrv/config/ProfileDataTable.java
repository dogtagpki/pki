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
package com.netscape.admin.certsrv.config;

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
public class ProfileDataTable extends JTable
{

    public ProfileDataTable(TableModel model) {
        super(model);
    }

    public TableCellRenderer getCellRenderer(int row, int column) {
        TableColumn tableColumn = getColumnModel().getColumn(column);
        TableCellRenderer renderer = tableColumn.getCellRenderer();
        if (renderer == null) {
            Class c = getColumnClass(column);
            if( c.equals(Object.class) ) {
                Object o = getValueAt(row,column);
                if( o != null ) {
                    c = getValueAt(row,column).getClass();
                }
            }
            renderer = getDefaultRenderer(c);
        }
        return renderer;
    }

    public TableCellEditor getCellEditor(int row, int column) {
        TableColumn tableColumn = getColumnModel().getColumn(column);
        TableCellEditor editor = tableColumn.getCellEditor();
        if (editor == null) {
            Class c = getColumnClass(column);
            if( c.equals(Object.class) ) {
                Object o = getValueAt(row,column);
                if( o != null )
                    c = getValueAt(row,column).getClass();
            }
            editor = getDefaultEditor(c);
        }
        return editor;
    }
}

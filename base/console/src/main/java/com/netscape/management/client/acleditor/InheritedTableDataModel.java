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
package com.netscape.management.client.acleditor;

import javax.swing.table.TableCellEditor;

import com.netscape.management.client.console.ConsoleInfo;

/**
 * Data model for the inherited rules table.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/30/97
 */

public class InheritedTableDataModel extends TableDataModel {
    public InheritedTableDataModel(DataModelFactory dmf, ConsoleInfo ds) {
        super(dmf, null, ds);
    }

    public InheritedTableDataModel(DataModelFactory dmf,
            ConsoleInfo ds, String[] headers) {
        super(dmf, null, ds, headers);
    }

    public TableCellEditor getColumnCellEditor(int col) {
        return null;
    }

    public int getRowCount() {
        return 0;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        return checkValue("");
    }

    public void selectionNotify(int row, int col, int clickCount,
            CallbackAction cb) {
        return;
    }
}

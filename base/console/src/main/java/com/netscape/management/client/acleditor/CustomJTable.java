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

import javax.swing.JTable;
import javax.swing.table.TableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;

/**
 * Customize JTable which will workaround the JTable column creation problem.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.1 10/10/97
 */

public class CustomJTable extends JTable {
    public CustomJTable(DataModelAdapter dma) {
        super(dma);
    }

    public void doResize() {
        resizeAndRepaint();
    }

    public void createDefaultColumnsFromModel() {
        TableModel m = getModel();

        if (!(m instanceof DataModelAdapter)) {
            super.createDefaultColumnsFromModel();
            return;
        }

        DataModelAdapter model = (DataModelAdapter) m;

        if (model != null) {
            // Remove any current columns
            TableColumnModel cm = getColumnModel();
            cm.removeColumnModelListener(this);
            while (cm.getColumnCount() > 0)
                cm.removeColumn(cm.getColumn(0));

            // Create new columns from the data model info
            for (int i = 0; i < model.getColumnCount(); i++) {
                int width = model.getColumnWidth(i);
                TableCellRenderer renderer = model.getColumnCellRenderer(i);
                TableCellEditor editor = model.getColumnCellEditor(i);

                // Now create the new column
                TableColumn newColumn = new TableColumn(i);
                newColumn.setIdentifier(model.getColumnIdentifier(i));
                if (model.getHeaderVisible())
                    newColumn.setHeaderValue(model.getColumnName(i));
                if (renderer != null)
                    newColumn.setCellRenderer(renderer);
                if (editor != null)
                    newColumn.setCellEditor(editor);
                if (width > 0) {
                    newColumn.setMaxWidth(width);
                    newColumn.setMinWidth(width);
                    newColumn.setWidth(width);
                }

                addColumn(newColumn);
            }

            cm.addColumnModelListener(this);
        }
    }
}

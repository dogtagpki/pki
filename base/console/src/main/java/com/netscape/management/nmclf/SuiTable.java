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

import java.awt.Component;
import java.awt.Dimension;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JViewport;
import javax.swing.UIManager;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/**
 * @deprecated replaced by Table
 * @see #com.netscape.management.client.components.Table
 */
@Deprecated
public class SuiTable extends JTable {

    public SuiTable(Vector rowData, Vector columnName) {
        super(rowData, columnName);
        setShowGrid(false);
        setIntercellSpacing(new Dimension(0, 0));
        setColumnSelectionAllowed(false);
        setDefaultRenderer(Object.class, new SuiTableCellRenderer());
    }

   /**
     * @overrides JTable@getScrollableTracksViewportWidth
     */
    public boolean getScrollableTracksViewportWidth()
    {
        Component parent =  getParent();
        if (parent != null && parent instanceof JViewport) {
            return (getPreferredSize().width < parent.getSize().width);
        }
        return false;
    }

    /**
     * @overrides JTable@getScrollableTracksViewportHeight
     */
    public boolean getScrollableTracksViewportHeight()
    {
        Component parent =  getParent();
        if (parent != null && parent instanceof JViewport) {
            return (getPreferredSize().height < parent.getSize().height);
        }
        return false;
    }

    public SuiTable() {
        super();
        setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        setShowGrid(false);
        setIntercellSpacing(new Dimension(0, 0));
        setColumnSelectionAllowed(false);
        setDefaultRenderer(Object.class, new SuiTableCellRenderer());
    }

    public SuiTable(TableModel model) {
        this();
        setModel(model);
        setDefaultRenderer(Object.class, new SuiTableCellRenderer());
    }

    public void sizeColumnsToFit(boolean lastColumnOnly) {
        if (getWidth() > 0)
            super.sizeColumnsToFit(lastColumnOnly);
    }

    public void setColumnWidth(int index, int width) {
        TableColumnModel columnModel = getColumnModel();
        TableColumn column = columnModel.getColumn(index);
        if (column != null && width > 0)
            column.setWidth(width);
    }

    static public JScrollPane createScrollPaneForTable(JTable aTable) {
        JScrollPane scrollPane = new SuiScrollPane(aTable);
        scrollPane.setColumnHeaderView(aTable.getTableHeader());
        scrollPane.getViewport().setBackingStoreEnabled(true);
        scrollPane.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));
        scrollPane.setBackground(UIManager.getColor("window"));
        return scrollPane;
    }

    public void setModel(TableModel model) {
        super.setModel(model);
        JTableHeader header = getTableHeader();
        if (header != null) {
            header.setUpdateTableInRealTime(false); // improved performance
            Enumeration enumeration = header.getColumnModel().getColumns();
            while (enumeration.hasMoreElements()) {
                TableColumn column =
                        (TableColumn) enumeration.nextElement();
                column.setHeaderRenderer(new SuiTableHeaderRenderer());
            }
        }
    }

    /**
      * This method overrides the method in JTable to use a custom TableColumn
      * which uses the SuiTableHeaderRenderer.
      *
      * @see  JTable#createDefaultColumnsFromModel()
      */
    public void createDefaultColumnsFromModel() {
        TableModel m = getModel();
        if (m != null) {
            // Remove any current columns
            TableColumnModel cm = getColumnModel();
            cm.removeColumnModelListener(this);
            while (cm.getColumnCount() > 0)
                cm.removeColumn(cm.getColumn(0));

            // Create new columns from the data model info
            for (int i = 0; i < m.getColumnCount(); i++) {
                TableColumn newColumn = new SuiTableColumn(i);
                addColumn(newColumn);
            }
            cm.addColumnModelListener(this);
        }
    }
}

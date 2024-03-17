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

import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;

import com.netscape.management.client.util.ResourceSet;

/**
 * The DataModelAdapter class is designed to be a base class for
 * every TableDataModel used within the ACL Editor. It provides
 * a standard TableDatModel behavior with the following features:
 * named or numerical column identifiers, fully editable cells,
 * implementation of an improved interface for CellEditor and
 * CellRenderer auto-creation (used by the the CustomJTable class),
 * the ability to specify the visibility of the column headers,
 * and basic table editing primitives for row manipulation.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/12/97
 */
public abstract class DataModelAdapter extends AbstractTableModel implements ACLEditorConstants {
    protected ResourceSet resources;
    protected String name;
    protected boolean headerVisible;
    protected String[] headerNames;

    // DT 8/19/98 Hack to pass the ACL through to the UserGroupDataModel
    // without modifying the APIs during API freeze. Ideally, the acl
    // object should be passed in the DataModelFactory call to create
    // the UserGroupDataModel.
    protected Object callerData = null;

    public Object getCallerData() {
        return callerData;
    }
    public void setCallerData(Object data) {
        callerData = data;
    }

    /**
      * Creates a DataModelAdapter, with visible column headers and
      * numerical (Integer) column identifiers.
      *
      * @param rs an ResourceSet object.
      * @param _name the base resource name for this DataModelAdapter,
      *  used for ResourceSet lookups.
      */
    public DataModelAdapter(ResourceSet rs, String _name) {
        this(rs, _name, true, null);
    }

    /**
      * Creates a DataModelAdapter, with visible column headers and
      * named column identifiers, using the _headerNames array
      * parameter.
      *
      * @param rs an ResourceSet object.
      * @param _name the base resource name for this DataModelAdapter,
      *  used for ResourceSet lookups.
      * @param _headerNames an array of column name identifiers, to
      *  replace the Integer column identifiers that would otherwise
      *  be used. If null, numerical (Integer) column identifiers
      *  will be used.
      */
    public DataModelAdapter(ResourceSet rs, String _name,
            String[]_headerNames) {
        this(rs, _name, true, _headerNames);
    }

    /**
      * Creates a DataModelAdapter, with visible column headers and
      * named column identifiers, using the _headerNames array
      * parameter. Column header visibility is specified by the
      * _headerVisible parameter.
      *
      * @param rs an ResourceSet object.
      * @param _name the base resource name for this DataModelAdapter,
      *  used for ResourceSet lookups.
      * @param _headerVisible specifies whether the column headers
     		will be visible.
      * @param _headerNames an array of column name identifiers, to
      *  replace the Integer column identifiers that would otherwise
      *  be used. If null, numerical (Integer) column identifiers
      *  will be used.
      */
    public DataModelAdapter(ResourceSet rs, String _name,
            boolean _headerVisible, String[]_headerNames) {
        resources = rs;
        name = _name;
        headerVisible = _headerVisible;
        headerNames = _headerNames;
    }

    /**
      * Returns the current boolean value for column header visibility.
      *
      * @return the current boolean value for column header visibility.
      */
    public boolean getHeaderVisible() {
        return headerVisible;
    }

    /**
      * Sets the boolean value for column header visibility. Must be followed
      * by a call to CustomJTable.createDefaultColumnsFromModel() to have
      * any effect. Note that CustomJTable.createDefaultColumnsFromModel() is
      * called automatically during initial CustomJTable creation.
      *
      * @param the new boolean value for column header visibility.
      * @return the current boolean value for column header visibility.
      */
    public void setHeaderVisible(boolean val) {
        headerVisible = val;
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the String to be used in the column header for column #col.
      */
    public String getColumnName(int col) {
        if (headerNames == null)
            return resources.getString(name, "column" + col + "Header");
        return resources.getString(name, headerNames[col] + "Header");
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the columnIdentifier corresponding to column #col.
      */
    public Object getColumnIdentifier(int col) {
        if (headerNames == null)
            return Integer.valueOf(col);
        return headerNames[col];
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param columnIdentifier a columnIdentifier Object.
      * @return the int column index corresponding to columnIdentifier.
      */
    public int getColumnIndex(Object columnIdentifier) {
        if (headerNames == null)
            return((Integer) columnIdentifier).intValue();

        String name = (String) columnIdentifier;

        for (int i = 0 ; i < headerNames.length ; i++) {
            if (name.equals(headerNames[i]))
                return i;
        }

        return -1;
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the String to be used as the tool tip for column #col.
      */
    public String getColumnToolTip(int col) {
        if (headerNames == null)
            return resources.getString(name, "column" + col + "ToolTip");
        return resources.getString(name, headerNames[col] + "ToolTip");
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the TableCellRenderer to be used column #col.
      */
    public TableCellRenderer getColumnCellRenderer(int col) {
        DefaultTableCellRenderer dtcr = new DefaultTableCellRenderer();
        dtcr.setHorizontalAlignment(SwingConstants.CENTER);
        dtcr.setToolTipText(getColumnToolTip(col));
        return dtcr;
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the TableCellEditor to be used column #col.
      */
    public TableCellEditor getColumnCellEditor(int col) {
        return null;
    }

    /**
      * Part of the improved column creation interface.
      *
      * @param col the integer column number, left to right, starting with 0.
      * @return the int width of column #col, or -1 if the column width should
      *  be set accordingly for the width of the column header String.
      */
    public int getColumnWidth(int col) {
        return -1;
    }

    /**
      * Part of the JTable automatic column creation interface.
      * This was a singularly lousy API choice by the swing folks, as you
      * cannot modify the JComponent created from this class before a
      * TableCellRenderer or TableCellEditor is created from it (although
      * you can retrieve the JComponent later and modify it...at your own
      * risk...)
      *
      * @param column the integer column number, left to right, starting with 0.
      * @return a valid, fully-qualified Class Object.
      */
    public Class getColumnClass(int column) {
        return((Object) this).getClass();
    }

    /**
      * Returns the boolean value which determines if the specified cell
      * is editable or not. By default, all DataModelAdapter-based cells
      * are editable.
      *
      * @param rowIndex the integer row number, top to bottom, starting with 0.
      * @param columnIdentifier the integer column number, left to right, starting with 0.
      */
    public boolean isCellEditable(int rowIndex, int columnIdentifier) {
        return true;
    }

    /**
      * Returns the base resource name for this DataModelAdapter,
      * used for ResourceSet lookups.
      *
      * @return the base resource name for this DataModelAdapter, used
      *  for ResourceSet lookups.
      */
    public String getName() {
        return name;
    }

    /**
      * Sets the cell value at (rowIndex, columnIdentifier). By default, this
      * method does nothing.
      *
      * @param value the new value.
      * @param rowIndex the integer row number, top to bottom, starting with 0.
      * @param columnIdentifier the integer column number, left to right, starting with 0.
     public void setValueAt(Object value, int rowIndex, int columnIdentifier)
     {
     	 System.err.println("DataModelAdapter:setValueAt():unimplemented");
     }

     /**
      * Gets the cell value at (rowIndex, columnIdentifier). This method must be
      * implemented.
      *
      * @param rowIndex the integer row number, top to bottom, starting with 0.
      * @param columnIdentifier the integer column number, left to right, starting with 0.
      * @return the value Object to be passed to the TableCellRenderer.
      */
    public abstract Object getValueAt(int rowIndex, int columnIdentifier);

    /**
     * Gets the current number of visible rows in the table. This method must be
     * implemented.
     *
     * @return the int number of rows in the table.
     */
    public abstract int getRowCount();

    /**
     * Gets the current number of visible columns in the table. If headerNames
     * is non-null, this function returns the length of that array. If you
     * are not using named column identifiers, you *must* override this function
     * (as it returns 0 in the absence of a headerNames array).
     *
     * @return the int number of columns in the table.
     */
    public int getColumnCount() {
        if (headerNames != null)
            return(headerNames.length);
        return 0;
    }

    /**
      * Part of the primitive row manipulation interface. Adds a new row
      * after the currently selected row, or appends the new row to the
      * end of the table if no row is selected.
      *
      * @param selection the currently selected row number, or -1 if no
      *  row is selected.
      */
    protected abstract void addRow(int selection);

    /**
     * Part of the primitive row manipulation interface. Deletes the
     * currently selected row, if any.
     *
     * @param selection the currently selected row number, or -1 if no
     *  row is selected.
     */
    protected abstract void deleteRow(int selection);

    /**
     * Part of the primitive row manipulation interface. Moves the
     * currently selected row up or down one row, according to the
     * value of the up parameter, if possible.
     *
     * @param selection the currently selected row number, or -1 if no
     *  row is selected.
     * @param up the boolean value for the move direction. true is up,
     *  false is down.
     */
    protected abstract void moveRow(int selection, boolean up);

    /**
     * A means to indicate if data elements are willing to accept focus.
     */
    protected boolean isFocusEnabled() {
        return true;
    }
}

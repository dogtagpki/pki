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
package com.netscape.management.client.security;

import java.util.*;
import javax.swing.table.*;


class ListTableModel extends AbstractTableModel {

    Vector _header;

    Vector _rowData;

    //Vector _tableModelListener;

    public ListTableModel(Vector columnIdentifier, Vector rowData) {
        this._header = columnIdentifier;
        this._rowData = rowData;
    }

    public boolean isCellEditable(int row, int column) { 
	return false; 
    }

    public void setRowData(Vector rowData) {
        _rowData = rowData;
    }

    public int getRowCount() {
        return _rowData.size();
    }

    public int getColumnCount() {
        return _header.size();
    }

    public String getColumnName(int columnIndex) {
        return (columnIndex >= _header.size() ? "":
                (String)(_header.elementAt(columnIndex)));
    }

    public Object getValueAt(int rowIndex, int columnIndex) {

        return ((Vector)(_rowData.elementAt(rowIndex))).elementAt(columnIndex);
    }

    public void deleteRow(int rowIndex) {
        try {
            _rowData.removeElementAt(rowIndex);
        } catch (Exception e) {}
    }

    //remove the first row it encounter that contains 
    //the matching string.
    public void deleteRow(String matchString) {
	for (int i=getRowCount()-1; i>=0; i--) {
	    for (int j=getColumnCount()-1; j>=0; j--) {
		if (getValueAt(i, j).toString().equals(matchString)) {
		    deleteRow(i);
		}
	    }
	}
    }

    public int getSelectedRow(String matchString) {
	for (int i=getRowCount()-1; i>=0; i--) {
	    for (int j=getColumnCount()-1; j>=0; j--) {
		if (getValueAt(i, j).toString().equals(matchString)) {
		    return i;
		}
	    }
	}
	return -1;
    }

    public int getSelectedRow(int columnIndex, String matchString) {
	String lcmatchString = matchString.toLowerCase();
	for (int i=getRowCount()-1; i>=0; i--) {
	    if (getValueAt(i, columnIndex).toString().toLowerCase().equals(lcmatchString)) {
		return i;
	    }
	}
	return -1;
    }

    public Object getObject(int rowIndex) {
	return _rowData.elementAt(rowIndex);
    }
}

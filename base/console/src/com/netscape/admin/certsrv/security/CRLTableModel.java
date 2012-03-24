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
package com.netscape.admin.certsrv.security;

import java.util.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;


class CRLTableModel extends AbstractTableModel {

    Vector _header;
    Vector _rowData = new Vector();
    Vector _tableModelListener = new Vector();

    public CRLTableModel(Vector CRL, Vector columnIdentifier) {
        update(CRL, columnIdentifier);
    }

    public void update(Vector CRL, Vector columnIdentifier) {
        _header = columnIdentifier;
        _rowData = CRL;
    }

    public void addRow(String issuer, String expires, String type) {
        Vector row = new Vector();
        row.addElement(issuer);
        row.addElement(expires);
        row.addElement(type);
        _rowData.addElement(row);
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
        Object o = null;

        try {
            o = ((Vector)(_rowData.elementAt(rowIndex))).elementAt(
                    columnIndex);
        } catch (Exception e) {}

        return o;
    }


    public void deleteRow(int rowIndex) {
        try {
            _rowData.removeElementAt(rowIndex);
        } catch (Exception e) {}
    }

    public void deleteAllRows() {
        _rowData.removeAllElements();
    }

    public void addTableModelListener(TableModelListener l) {
        _tableModelListener.addElement(l);
    }

    public void removeTableModelListener(TableModelListener l) {
        _tableModelListener.removeElement(l);
    }
}


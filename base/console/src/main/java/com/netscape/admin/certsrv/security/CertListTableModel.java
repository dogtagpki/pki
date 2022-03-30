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

import java.util.Vector;

import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;

/**
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class CertListTableModel extends AbstractTableModel {

    Vector<String> _header;

    Vector<CertBasicInfo> _rowData = new Vector<>();

    Vector<TableModelListener> _tableModelListener = new Vector<>();

    public CertListTableModel(Vector<String> columnIdentifier, Vector<CertBasicInfo> certList) {
        _header = columnIdentifier;
        _rowData = certList;
    }

    public void setRowData(Vector<CertBasicInfo> rowData) {
        _rowData = rowData;
    }

    @Override
    public int getRowCount() {
        return _rowData.size();
    }

    @Override
    public int getColumnCount() {
        return _header.size();
    }

    @Override
    public String getColumnName(int columnIndex) {
        return (columnIndex >= _header.size() ? "":
                (String)(_header.elementAt(columnIndex)));
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Object o = null;

        try {
            o = (_rowData.elementAt(rowIndex)).
                    getCertInfo((_header.elementAt(columnIndex)));
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

    public CertBasicInfo getRow(int index) {
        return index < _rowData.size() ?
                (CertBasicInfo)(_rowData.elementAt(index)) : null;
    }

    @Override
    public void addTableModelListener(TableModelListener l) {
        _tableModelListener.addElement(l);
    }

    @Override
    public void removeTableModelListener(TableModelListener l) {
        _tableModelListener.removeElement(l);
    }
}

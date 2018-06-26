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

import java.util.Vector;

import javax.swing.table.AbstractTableModel;

/**
 * Policy Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfilePolicyEditDataModel extends AbstractTableModel
{
  Vector<Vector<Object>> rowData;
  Vector<String> columnNames;

  public ProfilePolicyEditDataModel()
  {
  }

  public void setInfo(Vector<Vector<Object>> _rowData, Vector<String> _columnNames)
  {
    rowData = _rowData;
    columnNames = _columnNames;
  }

  public String getColumnName(int column)
  {
     return columnNames.elementAt(column).toString();
  }
  public int getRowCount()
  {
    return rowData.size();
  }
  public int getColumnCount()
  {
    return columnNames.size();
  }

  public Object getValueAt(int row, int column)
  {
    return rowData.elementAt(row).elementAt(column);
  }

  public boolean isCellEditable(int row, int column)
  {
    if (column == 1)
     return true;
    return false;
  }

  public void setValueAt(Object value, int row, int column)
  {
    rowData.elementAt(row).setElementAt(value, column);
    fireTableCellUpdated(row, column);
  }
}

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
package com.netscape.management.client.logging;

import java.util.*;
import javax.swing.table.*;


/**
 * Implements data model for LogViewer.
 *
 * @see ILogViewerModel
 */
public abstract class LogViewerModel extends DefaultTableModel implements ILogViewerModel {
    public static long UPDATE_INTERVAL = 20000; // in millis
    public static int BUFFER_LENGTH = 100; // in rows
    protected long _lastLogLengthCheckTime;
    protected int _rowOffset = Integer.MAX_VALUE;

    /**
     * Constructs LogViewerModel set with the default row buffer length of 100.
     */
    public LogViewerModel() {
        setNumRows(BUFFER_LENGTH);
    }



    /**
      * Constructs LogViewerModel with the default row buffer length of 100,
      * and a specified number of initial columns.
      *
      * @param numColumns	integer specifying number of columns in table
      */
    public LogViewerModel(int numColumns) {
        super(BUFFER_LENGTH, numColumns);
    }

    /**
      * constructor.  Constructs a DefaultTableModel with as many columns as there
      * are elements in columnIds and BUFFER_LENGTH of null object values.
      * @param columnIds Vector of Column names
      */
    public LogViewerModel(Vector columnIds) {
        super(columnIds, BUFFER_LENGTH);
    }

    /**
      * constructor.  Constructs a DefaultTableModel with as many columns as there
      * are elements in columnIds and BUFFER_LENGTH of null object values.
      * @param columnIds Array of Column names
      */
    public LogViewerModel(Object[] columnIds) {
        super(columnIds, BUFFER_LENGTH);
    }

    /**
       * Returns detail information for a given cell.  If the Object
     * is a Component, it is set in the detail pane, otherwise the
     * toString() value of object is displayed as text.
     * Called by LogViewer
       */
    public Object getDetailInfo(int row, int column) {
        return null;
    }

    /**
       * Returns a boolean value indicating whether any log data
     * has detail information.
     * Called by LogViewer
       */
    public boolean hasDetailInfo() {
        return false;
    }

    /**
       * Returns a component that displays a log filter.
     * Called by LogViewer
       */
    public IFilterComponent getFilterComponent(Object viewInstance) {
        return (IFilterComponent) null;
    }

    /**
       * Sets an object representing a log filter.   This object
     * is obtained from the IFilterComponent.
     * Called by LogViewer
       */
    public void setFilter(Object viewInstance, Object filter) {
    }

    /**
       * Get the row display offset
       */
    public int getRowOffset() {
        return _rowOffset;
    }

    /**
       * Get the row display offset
       */
    public int getBufferLength() {
        return BUFFER_LENGTH;
    }

    /**
      * @returns the number of rows in the LogViewer
      */
    public int getRowCount() {
        int logLength = getLogLength();
        if (logLength == -1)
            logLength = super.getRowCount();
        return logLength;
    }

    /**
      * @return the Object at the specified row and column
      */
    public Object getValueAt(int row, int col) {
        if ((row < _rowOffset) || (row >= _rowOffset + BUFFER_LENGTH)) {
            _rowOffset = row;
            populateRows(_rowOffset, BUFFER_LENGTH);
        }

        return super.getValueAt(row - _rowOffset, col);
    }

    /**
      * @return the Column name of the column at the specified position.
      */
    public String getColumnIdentifier(int column) {
        return (String) columnIdentifiers.elementAt(column);
    }

    /**
       * Get the row buffer size
       */
    public void tableDataChanged() {
        fireTableDataChanged();
    }

    /**
       * Defines if cells are editable
       */
    public boolean isCellEditable(int x, int y) {
        return false;
    }

    /**
      * Populates numRows rows of the LogViewer table starting at row rowStartIndex
      * @param rowStartIndex starting row
      * @param numRows number of rows to be populated
      */
    public abstract void populateRows(int rowStartIndex, int numRows);

    /**
     * @return the number of rows in the log file
     */
    public abstract int getLogLength();
}

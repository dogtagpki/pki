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
package com.netscape.admin.certsrv;

import java.util.*;
import javax.swing.table.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.logging.*;

/**
 * Generic base class for the JTable data container that will
 * CACHE the data object retrieved.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 * @see javax.swing.table.AbstractTableModel
 */
public class  CMSContentTableModel extends CMSTableModel {

    /*==========================================================
     * variables
     *==========================================================*/
    protected Vector mObjectContainer = new Vector();     // object container

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSContentTableModel() {
        super();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Returns the number of rows in the table
     * @return number of rows
     */
    public int getRowCount() {
        return mObjectContainer.size();
    }

    /**
     * Add data row and data object associated with this row
     * @param values row values for the table
     * @param obj data object
     */
    public void addRow(Vector values, Object obj) {
        super.addRow(values);
        mObjectContainer.addElement(obj);
    }

    /**
     * Remove row at the specified index position
     * @param index row index to be removed
     */
    public void removeRow(int index)
        throws ArrayIndexOutOfBoundsException
    {
        Debug.println("CMSContentDataModel: removeRow() - start");
        mObjectContainer.removeElementAt(index);
        super.removeRow(index);
        Debug.println("CMSContentDataModel: removeRow() - end");
    }

    /**
     * clean up the table including the datat objects
     */
    public void removeAllRows() {
        super.removeAllRows();
        mObjectContainer.removeAllElements();
    }

    /**
     * retrieve data object associated with specified row
     * @param row table row number
     * @return data object
     */
    public Object getObjectValueAt(int row) {
        return mObjectContainer.elementAt(row);
    }

}

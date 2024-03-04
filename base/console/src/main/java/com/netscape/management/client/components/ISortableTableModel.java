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
package com.netscape.management.client.components;

/**
 * An interface used to implement sorting behavior for a TableModel.
 * This interface is recognized by DetailTable, which provides
 * the UI (arrows on table headers) and interaction behavior.
 * 
 * @author Andy Hakim
 */
interface ISortableTableModel
{
    /**
     * Event notification that the table needs to be sorted.
     * This event is triggered when a user clicks on a column in the table header.
     * After the data has been sorted, fire a table changed event.
     * 
     * @param column the index of the column to sort on
     * @param ascending indicates sorting order, true=ascending, false=descending
     */
    public void sortByColumn(int column, boolean ascending);
}

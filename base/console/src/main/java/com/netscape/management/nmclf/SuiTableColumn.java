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

import javax.swing.table.*;

/**
 * This class creates a table column component which returns
 * SuiTableHeaderRenderer for getHeaderRenderer().
 *
 * @author Peter Lee (phlee@netscape.com)
 * @todo may not be necessary because SuiTableUI does this automatically
 */
public class SuiTableColumn extends TableColumn {

    public SuiTableColumn() {
        super();
        setHeaderRenderer(new SuiTableHeaderRenderer());
    }

    public SuiTableColumn(int modelIndex) {
        super(modelIndex);
        setHeaderRenderer(new SuiTableHeaderRenderer());
    }

    public SuiTableColumn(int modelIndex, int width) {
        super(modelIndex, width);
        setHeaderRenderer(new SuiTableHeaderRenderer());
    }

    public SuiTableColumn(int modelIndex, int width,
            TableCellRenderer cellRenderer, TableCellEditor cellEditor) {
        super(modelIndex, width, cellRenderer, cellEditor);
        setHeaderRenderer(new SuiTableHeaderRenderer());
    }
}

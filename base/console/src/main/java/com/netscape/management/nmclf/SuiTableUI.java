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

import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.plaf.*;
import javax.swing.plaf.basic.*;

/**
 * A UI for JTable to set various default properties and improve
 * visual appearance.   Specicially:
 *
 * - the default cell renderer for Object.class is set to SuitableCellRenderer
 * - setUpdateTableInRealTime(false)
 * - all table column headers are set to SuiTableHeaderRenderer
 */
public class SuiTableUI extends BasicTableUI implements SuiConstants {
    public SuiTableUI() {
        super();
    }

    public static ComponentUI createUI(JComponent c) {
        return new SuiTableUI();
    }

    public void installUI(JComponent c) {
        super.installUI(c);
        table = (JTable) c;
                JTableHeader header = table.getTableHeader();
                header.setUpdateTableInRealTime(false); // improved performance
                Enumeration enumeration =
                        header.getColumnModel().getColumns();
        while (enumeration.hasMoreElements()) {
            TableColumn column = (TableColumn) enumeration.nextElement();
            column.setHeaderRenderer(new SuiTableHeaderRenderer());
        }
    }
}

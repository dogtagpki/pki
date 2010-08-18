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

import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;

/**
 * Manage Keys data model - represents the instance
 * table information
 *
 * @author Khai
 * @version $Revision$, $Date$
 */
public class ListKeysModel extends CMSTableModel
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String COL1 = "KEYNAME";
    public static final String COL2 = "SERIALNUMBER";
    public static final String COL3 = "ISSUERNAME";  
    public static final String COL4 = "TOKENNAME";
     
    private static String[] mColumns = {COL1};

    /*==========================================================
     * constructors
     *==========================================================*/
    public ListKeysModel() {
        super();
        init(mColumns);
    }

    public boolean isCellEditable(int row, int col) {
        return false;
    }
}

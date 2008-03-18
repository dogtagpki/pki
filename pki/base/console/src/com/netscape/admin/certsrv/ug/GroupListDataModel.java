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
package com.netscape.admin.certsrv.ug;

import java.util.*;
import javax.swing.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Group List Data model - represents the group selection information
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class GroupListDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static String[] mColumns = {GROUPNAME};

    /*==========================================================
     * constructors
     *==========================================================*/
    public GroupListDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(Object data) {
        Vector v = new Vector();

        String entry = (String)data;
        String name;
        if (entry.startsWith(PrefixDef.PX_SYS))
            name = entry.substring(PrefixDef.PX_SYS.length());
        else
            name = entry.substring(PrefixDef.PX_DEF.length());

        v.addElement(new JLabel(name,
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USERGROUP),
            JLabel.LEFT));
        addRow(v, data);
    }
}

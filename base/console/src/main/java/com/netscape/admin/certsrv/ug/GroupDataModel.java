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

import java.util.Vector;

import javax.swing.JLabel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSContentTableModel;

/**
 * Group Data model - represents the group table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class GroupDataModel extends CMSContentTableModel {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String[] mColumns = {GROUPNAME, GROUPDESC};

    /*==========================================================
     * constructors
     *==========================================================*/
    public GroupDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(String name, String desc) {
        Vector<Object> v = new Vector<>();

        //XXX NEED TO CHANGE if we are going to have multi-column table
        v.addElement(new JLabel(name,
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USERGROUP),
            JLabel.LEFT));
        v.addElement(desc);
        addRow(v,name);
    }

}

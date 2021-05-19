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
import com.netscape.admin.certsrv.IDataProcessor;

/**
 * User List Data model - represents the single column user
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class UserListDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static String[] mColumns = {USERID};

    /*==========================================================
     * constructors
     *==========================================================*/
    public UserListDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    @Override
    public void processData(Object data) {
        Vector<Object> v = new Vector<>();

        //XXX NEED TO CHANGE if we are going to have multi-column table
        v.addElement(new JLabel((String)data,
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER),
            JLabel.LEFT));
        addRow(v, data);
    }

    /**
     * get user vector for comparison
     */
    public Vector<Object> getUsers() {
        return  (Vector<Object>) mObjectContainer.clone();
    }

}

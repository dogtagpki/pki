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
 * User Data model - represents the user table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class UserDataModel extends CMSContentTableModel {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String[] mColumns = {USERID, FULLNAME};

    /*==========================================================
     * constructors
     *==========================================================*/
    public UserDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(String uid, String name) {
        Vector v = new Vector();

        v.addElement(new JLabel(uid,
              CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER),
              JLabel.LEFT));
        v.addElement(name);    

        addRow(v,uid);
    }

    /**
     * get user vector for comparison
     */
    public Vector getUsers() {
        return  (Vector) mObjectContainer.clone();
    }

}

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
import com.netscape.management.client.util.*;

/**
 * Group Membership model - represents the group table information
 * We will need to store the user and group information in separate
 * vector also for comparison purpose.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class MemberDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String MEMBER_NAME = "MEMBER_NAME";
    public static final String MEMBER_TYPE = "MEMBER_TYPE";
    public static final String MEMBER_GROUP = "MEMBER_GROUP";
    public static final String MEMBER_USER = "MEMBER_USER";

    private static String[] mColumns = {MEMBER};

    private Vector mUsers = new Vector();
    private Vector mGroups = new Vector();

    /*==========================================================
     * constructors
     *==========================================================*/
    public MemberDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(Object data) {
        Vector v = new Vector();

        NameValuePairs rec = (NameValuePairs)data;

        Icon icon;
        icon = (rec.getValue(MEMBER_TYPE).equals(MEMBER_GROUP))?
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USERGROUP):
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER);

        String entry = rec.getValue(MEMBER_NAME);
        String name = entry;
        if(rec.getValue(MEMBER_TYPE).equals(MEMBER_GROUP)) {
            if (entry.startsWith(PrefixDef.PX_SYS))
                name = entry.substring(PrefixDef.PX_SYS.length());
            else
                name = entry.substring(PrefixDef.PX_DEF.length());
        }
        v.addElement(new JLabel(name,icon, JLabel.LEFT));
        addRow(v, data);
    }

    /**
     * clean up the table including the datat objects
     */
    public void removeAllRows() {
        super.removeAllRows();
        mObjectContainer.removeAllElements();
        mUsers.removeAllElements();
        mGroups.removeAllElements();
    }

    /**
     * Remove row at the specified index position
     * @param index row index to be removed
     */
    public void removeRow(int index)
        throws ArrayIndexOutOfBoundsException
    {
        Debug.println("MemberDataModel: removeRow() - start");
        NameValuePairs data = (NameValuePairs)getObjectValueAt(index);
        if (data.getValue(MEMBER_TYPE).equals(MEMBER_GROUP))
            mGroups.removeElement(data.getValue(MEMBER_NAME));
        else
            mUsers.removeElement(data.getValue(MEMBER_NAME));
        super.removeRow(index);
        Debug.println("MemberDataModel: removeRow() - end");
    }

    /**
     * Add data row and data object associated with this row
     * @param values row values for the table
     * @param obj data object
     */
    public void addRow(Vector values, Object obj) {
        super.addRow(values);
        mObjectContainer.addElement(obj);
        NameValuePairs rec = (NameValuePairs)obj;
        if (rec.getValue(MEMBER_TYPE).equals(MEMBER_GROUP))
            mGroups.addElement(rec.getValue(MEMBER_NAME));
        else
            mUsers.addElement(rec.getValue(MEMBER_NAME));
    }

    /**
     * get user vector for comparison
     */
    public Vector getUsers() {
        return (Vector)mUsers.clone();
    }

    /**
     * get group vector for comparison
     */
    public Vector getGroups() {
        return (Vector)mGroups.clone();
    }

}

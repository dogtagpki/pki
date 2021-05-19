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

import javax.swing.Icon;
import javax.swing.JLabel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSContentTableModel;
import com.netscape.admin.certsrv.IDataProcessor;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.PrefixDef;
import com.netscape.management.client.util.Debug;

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

    private Vector<String> mUsers = new Vector<>();
    private Vector<String> mGroups = new Vector<>();

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
    @Override
    public void processData(Object data) {
        Vector<Object> v = new Vector<>();

        NameValuePairs rec = (NameValuePairs)data;

        Icon icon;
        icon = (rec.get(MEMBER_TYPE).equals(MEMBER_GROUP))?
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USERGROUP):
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER);

        String entry = rec.get(MEMBER_NAME);
        String name = entry;
        if(rec.get(MEMBER_TYPE).equals(MEMBER_GROUP)) {
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
    @Override
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
    @Override
    public void removeRow(int index)
        throws ArrayIndexOutOfBoundsException
    {
        Debug.println("MemberDataModel: removeRow() - start");
        NameValuePairs data = (NameValuePairs)getObjectValueAt(index);
        if (data.get(MEMBER_TYPE).equals(MEMBER_GROUP))
            mGroups.removeElement(data.get(MEMBER_NAME));
        else
            mUsers.removeElement(data.get(MEMBER_NAME));
        super.removeRow(index);
        Debug.println("MemberDataModel: removeRow() - end");
    }

    /**
     * Add data row and data object associated with this row
     * @param values row values for the table
     * @param obj data object
     */
    @Override
    public void addRow(Vector<Object> values, Object obj) {
        super.addRow(values);
        mObjectContainer.addElement(obj);
        NameValuePairs rec = (NameValuePairs)obj;
        if (rec.get(MEMBER_TYPE).equals(MEMBER_GROUP))
            mGroups.addElement(rec.get(MEMBER_NAME));
        else
            mUsers.addElement(rec.get(MEMBER_NAME));
    }

    /**
     * get user vector for comparison
     */
    public Vector<String> getUsers() {
        return (Vector<String>)mUsers.clone();
    }

    /**
     * get group vector for comparison
     */
    public Vector<String> getGroups() {
        return (Vector<String>)mGroups.clone();
    }

}

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

/**
 * Auth Plugin Implementation Data model - represents the implementation
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthImplDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String IMPL_NAME = "NAME";
    public static final String IMPL_CLASS = "CLASS";
    public static final String IMPL_DESC = "DESC";
    public static final String IMPL_TYPE = "TYPE";

    private static String[] mColumns = {POLICY_IMPL, CLASSNAME};

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthImplDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(Object data) {
        Vector v = new Vector();
        NameValuePairs obj = (NameValuePairs) data;
        JLabel label = new JLabel(obj.get(IMPL_NAME),
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_AUTH_PLUGIN),
            JLabel.LEFT);
        if(!obj.get(IMPL_DESC).trim().equals(""))
            label.setToolTipText(obj.get(IMPL_DESC));
        v.addElement(label);
        v.addElement(obj.get(IMPL_CLASS));
        //v.addElement(obj.getValue(IMPL_DESC));
        addRow(v, data);
    }

}

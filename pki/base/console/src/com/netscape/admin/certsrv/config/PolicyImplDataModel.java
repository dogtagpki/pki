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
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;

/**
 * Policy Implementation Data model - represents the implementation
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class PolicyImplDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String IMPL_NAME = "NAME";
    public static final String IMPL_CLASS = "CLASS";
    public static final String IMPL_DESC = "DESC";
     
    private static String[] mColumns = {POLICY_IMPL, CLASSNAME};

    /*==========================================================
     * constructors
     *==========================================================*/
    public PolicyImplDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(Object data) {
        Vector v = new Vector();
        NameValuePairs obj = (NameValuePairs) data;
        v.addElement(new JLabel(obj.getValue(IMPL_NAME),
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE_PLUGIN),
            JLabel.LEFT));
        v.addElement(obj.getValue(IMPL_CLASS));
        //v.addElement(obj.getValue(IMPL_DESC));
        addRow(v, data);
    }

}

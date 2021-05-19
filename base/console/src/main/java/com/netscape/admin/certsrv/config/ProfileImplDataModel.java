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

import java.util.Vector;

import javax.swing.JLabel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSContentTableModel;
import com.netscape.admin.certsrv.IDataProcessor;
import com.netscape.certsrv.common.NameValuePairs;

/**
 * Policy Implementation Data model - represents the implementation
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileImplDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String IMPL_NAME = "NAME";
    public static final String IMPL_CLASS = "CLASS";
    public static final String IMPL_TYPE = "TYPE";
    public static final String IMPL_DESC = "DESC";

    private static String[] mColumns = {POLICY_IMPL, IMPL_TYPE, CLASSNAME};

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileImplDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    @Override
    public void processData(Object data) {
        Vector<Object> v = new Vector<>();
        NameValuePairs obj = (NameValuePairs) data;
        v.addElement(new JLabel(obj.get(IMPL_NAME),
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE_PLUGIN),
            JLabel.LEFT));
        v.addElement(obj.get(IMPL_TYPE));
        v.addElement(obj.get(IMPL_CLASS));
        //v.addElement(obj.getValue(IMPL_DESC));
        addRow(v, data);
    }

}

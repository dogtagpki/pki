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
 * Policy instance Data model - represents the instance
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class ProfileRuleDataModel extends CMSRuleDataModel
{

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileRuleDataModel() {
        super();
    }

	protected String[] getColumns() {
		String x[] = {PROFILE_RULE, STATUS};
		return x;
	}

    public void processData(Object data) {
        Vector v = new Vector();
        NameValuePairs obj = (NameValuePairs) data;

        //XXX NEED TO ADD STUFF
        if (obj.get(RULE_STAT).equalsIgnoreCase("enabled")) {
            v.addElement(new JLabel(obj.get(RULE_NAME),
                    CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE),
                    JLabel.LEFT));
            v.addElement(mResource.getString("POLICYRULE_LABEL_ENABLED_LABEL"));
        } else {
            v.addElement(new JLabel(obj.get(RULE_NAME),
                    CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE_DISABLE),
                    JLabel.LEFT));
            v.addElement(mResource.getString("POLICYRULE_LABEL_DISABLED_LABEL"));
        }
        addRow(v, data);
        mRules.addElement(obj.get(RULE_NAME));
    }


}

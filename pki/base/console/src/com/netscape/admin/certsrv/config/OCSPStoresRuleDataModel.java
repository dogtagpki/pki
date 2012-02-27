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
import com.netscape.management.client.util.Debug;


/**
 * CRL Extensions instance Data model - represents the instance
 * table information
 *
 * @version $Revision$, $Date$
 */

public class OCSPStoresRuleDataModel extends CMSRuleDataModel
{

    /*==========================================================
     * constructors
     *==========================================================*/
    public OCSPStoresRuleDataModel() {
        super();
    }

    protected String[] getColumns() {
        Debug.println("PolicyRuleDataModel.getColumns()");
        String x[] = {OCSPSTORES_RULE, STATUS};
        return x;
    }

    public void processData(Object data) {
        Vector v = new Vector();
        NameValuePairs obj = (NameValuePairs) data;

        if (obj.get(RULE_STAT).equalsIgnoreCase("enabled")) {
            v.addElement(new JLabel(obj.get(RULE_NAME),
                    CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE),
                    JLabel.LEFT));
            v.addElement(mResource.getString("OCSPSTORESRULE_LABEL_ENABLED_LABEL"));       
        } else {
            v.addElement(new JLabel(obj.get(RULE_NAME),
                    CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE_DISABLE),
                    JLabel.LEFT));
            v.addElement(mResource.getString("OCSPSTORESRULE_LABEL_DISABLED_LABEL"));
        }
        addRow(v, data);
        mRules.addElement(obj.get(RULE_NAME));
    }

}

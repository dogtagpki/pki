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
 * Mapper instance Data model - represents the instance
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class MapperRuleDataModel extends CMSRuleDataModel
{

    /*==========================================================
     * constructors
     *==========================================================*/
    public MapperRuleDataModel() {
        super();
    }

	protected String[] getColumns() {
		Debug.println("MapperRuleDataModel.getColumns()");
		String x[] = {MAPPER_RULE, PLUGIN};
		return x;
	}

    public void processData(Object data) {
        Vector v = new Vector();
        NameValuePairs obj = (NameValuePairs) data;

        v.addElement(new JLabel(obj.get(RULE_NAME),
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE),
                  JLabel.LEFT));
        v.addElement(obj.get(RULE_IMPL));
        addRow(v, data);
    }


}

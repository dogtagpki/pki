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

import javax.swing.JFrame;

import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;

/**
 * Rule Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class RuleConfigDialog extends CMSBaseConfigDialog
{
    /*==========================================================
     * constructors
     *==========================================================*/
    public RuleConfigDialog(NameValuePairs nvp,
                JFrame parent,
                AdminConnection conn,
                String dest) {

        super(parent, dest);
		PREFIX = "RULECONFIGDIALOG";
		RAHELPINDEX =
			"configuration-ra-edit-rulerule-dbox-help";
		CAHELPINDEX =
			"configuration-ca-edit-rulerule-dbox-help";

        mImplName_token = Constants.PR_RULE_IMPL_NAME;
        mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_PUBLISHRULE;

        init(nvp,parent,conn,dest);
    }

}

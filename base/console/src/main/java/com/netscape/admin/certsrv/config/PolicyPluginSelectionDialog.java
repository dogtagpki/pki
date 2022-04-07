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

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.ScopeDef;

/**
 * Policy Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class PolicyPluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "POLICYSELECTIONDIALOG";
    private static final String CAHELPINDEX =
      "configuration-ca-add-policyrule-dbox-help";
    private static final String RAHELPINDEX =
      "configuration-ra-add-policyrule-dbox-help";
    private static final String KRAHELPINDEX =
      "configuration-kra-add-policyrule-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public PolicyPluginSelectionDialog(
			JFrame parent,
			AdminConnection conn,
			String dest,
			CMSPluginInstanceTab pluginType)
	{
        super(PREFIX, parent,conn, dest, pluginType);
        mScope         = ScopeDef.SC_POLICY_IMPLS;
        mInstanceScope = ScopeDef.SC_POLICY_RULES;
        mImageName     = CMSAdminResources.IMAGE_RULE_PLUGIN;
        if (dest.equals(DestDef.DEST_RA_POLICY_ADMIN))
            mHelpToken = RAHELPINDEX;
        else if (dest.equals(DestDef.DEST_KRA_POLICY_ADMIN))
            mHelpToken = KRAHELPINDEX;
        else
            mHelpToken = CAHELPINDEX;
        setDisplay();
    }

}

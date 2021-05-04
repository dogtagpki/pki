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

import javax.swing.JFrame;

import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.config.CMSBaseConfigDialog;
import com.netscape.admin.certsrv.config.CMSPluginInstanceTab;
import com.netscape.admin.certsrv.config.PluginSelectionDialog;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * Auth Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "AUTHRULE";
    //private static final String ADMINRULE = "adminAuth";
    //private static final String AGENTRULE = "agentAuth";

    private static final String HELPINDEX =
      "authentication-certsrv-authrules-help";

	private static final String DEST = DestDef.DEST_AUTH_ADMIN;

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthInstanceTab(CMSBaseResourceModel model) {
        super(model,DEST, PANEL_NAME );
    	RULE_NAME = AuthRuleDataModel.RULE_NAME;
    	RULE_IMPL = AuthRuleDataModel.RULE_IMPL;
    	RULE_TYPE = AuthRuleDataModel.RULE_TYPE;
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new AuthRuleDataModel();
		mScope = ScopeDef.SC_AUTH_MGR_INSTANCE;
        mHelpToken = HELPINDEX;
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    public CMSBaseConfigDialog makeNewConfigDialog(
            NameValuePairs nvp,
            JFrame parent,
            AdminConnection conn,
            String dest
            )
    {

        return new AuthConfigDialog(nvp,
            parent,
            conn,
            dest);
    }

    public PluginSelectionDialog getPluginSelectionDialog(
            JFrame parent,
            AdminConnection conn,
            String dest,
            CMSPluginInstanceTab pluginType
            )
    {
        return new AuthPluginSelectionDialog(parent,conn,dest,pluginType);
    }


    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    /*==========================================================
     * protected methods
     *==========================================================*/


    //=============================================
    // SEND REQUESTS TO THE SERVER SIDE
    //=============================================
}

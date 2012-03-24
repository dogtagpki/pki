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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.config.*;
import javax.swing.*;

import com.netscape.certsrv.common.*;

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
    private static final String ADMINRULE = "adminAuth";
    private static final String AGENTRULE = "agentAuth";

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

    private void delete() {

        mModel.progressStart();
        //get entry name
        NameValuePairs data = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of user
        try {
            mConnection.delete(DestDef.DEST_AUTH_ADMIN,
                               ScopeDef.SC_AUTH_MGR_INSTANCE,
                               data.get(RULE_NAME));
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        mModel.progressStop();
        //send comment to server and refetch the content
        refresh();

    }

    //this returns the configuration
    private NameValuePairs getConfig() throws EAdminException {
        NameValuePairs data = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        NameValuePairs response;
        response = mConnection.read(DestDef.DEST_AUTH_ADMIN,
                               ScopeDef.SC_AUTH_MGR_INSTANCE,
                               data.get(RULE_NAME),
                               new NameValuePairs());
        return response;
    }
}

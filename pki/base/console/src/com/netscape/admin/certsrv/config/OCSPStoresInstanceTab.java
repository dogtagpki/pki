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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;


/**
 * CRL Extensions  -  Instances Management Tab
 *
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */

public class OCSPStoresInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "OCSPSTORESRULE";
    
    private final static String OCSPHELPINDEX = "configuration-ocsp-storeinstances-help";


	/*==========================================================
     * constructors
     *==========================================================*/
    public OCSPStoresInstanceTab(CMSBaseResourceModel model, String dest) {
        super(model,dest,PANEL_NAME);
        Debug.println("OCSPStoresInstanceTab::OCSPStoresInstanceTab(<model>,"+dest);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new OCSPStoresRuleDataModel();
        mScope = ScopeDef.SC_OCSPSTORES_RULES;
        RULE_NAME = OCSPStoresRuleDataModel.RULE_NAME; 
        RULE_IMPL = OCSPStoresRuleDataModel.RULE_IMPL;
        RULE_STAT = OCSPStoresRuleDataModel.RULE_STAT;  
        mHelpToken = OCSPHELPINDEX;
    }


    public CMSBaseConfigDialog makeNewConfigDialog(
            NameValuePairs nvp,
            JFrame parent,
            AdminConnection conn,
            String dest) 
    {
        return new OCSPStoresConfigDialog(nvp, parent, conn, dest);
    }

	public PluginSelectionDialog getPluginSelectionDialog(
            JFrame parent,
            AdminConnection conn,
            String dest,
            CMSPluginInstanceTab pluginType) 
    {
        return new OCSPStoresPluginSelectionDialog(parent, conn, dest, pluginType);
    }


    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("DEFAULT");
        mDelete = makeJButton("DELETE");
        mAdd.setEnabled(true);
        mDelete.setEnabled(false);
        mEdit = makeJButton("EDIT");
		JButton[] buttons = {mAdd, mEdit};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

	public void actionPerformed(ActionEvent e) {
		if (e.getSource().equals(mAdd)) {
			setDefault();
		} else {
			super.actionPerformed(e);
		}
	}

    private void setDefault() {

        mModel.progressStart();
        //get entry name
        NameValuePairs data = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow()); 
        NameValuePairs nvps = new NameValuePairs();

        //send comment to server for the removal of user
        try {
            mConnection.modify(DestDef.DEST_OCSP_ADMIN,
                               ScopeDef.SC_OCSPSTORE_DEFAULT,
                               data.getValue(RULE_NAME), nvps);
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

}

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

import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

/**
 * Log Instances Management Tab
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class LogInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "LOGRULE";

    private final static String HELPINDEX = "configuration-loginstances-help";


	/*==========================================================
     * constructors
     *==========================================================*/
    public LogInstanceTab(CMSBaseResourceModel model, String dest) {
        super(model,dest,PANEL_NAME);
		Debug.println("LogInstanceTab::LogInstanceTab(<model>,"+dest);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new LogRuleDataModel();
		mScope = ScopeDef.SC_LOG_RULES;
		RULE_NAME = LogRuleDataModel.RULE_NAME;
        RULE_IMPL = LogRuleDataModel.RULE_IMPL;
		RULE_STAT = LogRuleDataModel.RULE_STAT;

        mHelpToken = HELPINDEX;
    }


	@Override
    public CMSBaseConfigDialog makeNewConfigDialog(
			NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest
			)
	{

		return new LogConfigDialog(nvp,
			parent,
			conn,
			dest);
	}

	@Override
    public PluginSelectionDialog getPluginSelectionDialog(
			JFrame parent,
			AdminConnection conn,
			String dest,
			CMSPluginInstanceTab pluginType
			)
	{
		return new LogPluginSelectionDialog(parent,conn,dest,pluginType);
	}


}





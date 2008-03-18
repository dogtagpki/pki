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
 * Log Instances Management Tab
 *
 * @author Michelle Zhao
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
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





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
 * Jobs Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class JobsInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "JOBSRULE";

    private final static String HELPINDEX = "jobsscheduler-certsrv-jobrules-help";


	/*==========================================================
     * constructors
     *==========================================================*/
    public JobsInstanceTab(CMSBaseResourceModel model) {
        super(model,DestDef.DEST_JOBS_ADMIN,PANEL_NAME);
		Debug.println("JobsInstanceTab::JobsInstanceTab(<model>");
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new JobsRuleDataModel();
		mScope = ScopeDef.SC_JOBS_INSTANCE;
		RULE_NAME = JobsRuleDataModel.RULE_NAME;
		RULE_STAT = JobsRuleDataModel.RULE_STAT;

        mHelpToken = HELPINDEX;
    }


	public CMSBaseConfigDialog makeNewConfigDialog(
			NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest
			)
	{

		return new JobsConfigDialog(nvp,
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
		return new JobsPluginSelectionDialog(parent,conn,dest,pluginType);
	}


    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mEdit = makeJButton("EDIT");
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
		JButton[] buttons = {mAdd, mDelete, mEdit};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

}

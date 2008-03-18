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

import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Auth Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthPluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PREFIX = "AUTHSELECTIONDIALOG";

/*
    private final static String token = ";";
    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;
    protected DefaultListModel mDataModel;
    private CMSBaseResourceModel mModel;

    private JScrollPane mScrollPane;
    private JList mList;

    private JButton mOK, mCancel, mHelp;
*/

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthPluginSelectionDialog(JFrame parent,
					AdminConnection conn, 
					String dest,
					CMSPluginInstanceTab pluginType) {

		super(PREFIX,parent,conn,dest,pluginType);
		mScope = ScopeDef.SC_AUTH_IMPLS;
		mInstanceScope = ScopeDef.SC_AUTH_MGR_INSTANCE;
		mImageName = CMSAdminResources.IMAGE_RULE_PLUGIN;
		
    	mHelpToken = "authentication-certsrv-add-authrule-dbox-help";
		setDisplay();
/****
        super(model.getFrame(),true);
        mParentFrame = model.getFrame();
        mModel = model;
        mConnection = model.getServerInfo().getAdmin();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new DefaultListModel();
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(mParentFrame);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
***/
    }

    /*==========================================================
     * public methods
     *==========================================================*/



}

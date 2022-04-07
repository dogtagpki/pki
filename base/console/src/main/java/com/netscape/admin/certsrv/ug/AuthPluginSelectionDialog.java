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

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.config.CMSPluginInstanceTab;
import com.netscape.admin.certsrv.config.PluginSelectionDialog;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.ScopeDef;

/**
 * Auth Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
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

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

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;


/**
 * CRL Extensions  -  Instances Management Tab
 *
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */

@Deprecated(since="10.14.0", forRemoval=true)
public class CRLExtensionsInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "CRLEXTSRULE";

    private final static String CAHELPINDEX = "configuration-ca-crlinstances-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    public CRLExtensionsInstanceTab(CMSBaseResourceModel model, String dest) {
        super(model,dest,PANEL_NAME);
        Debug.println("CRLExtensionsInstanceTab::CRLExtensionsInstanceTab(<model>,"+dest);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new RuleRuleDataModel();
        mScope = ScopeDef.SC_CRLEXTS_RULES;
        RULE_NAME = CRLExtensionsRuleDataModel.RULE_NAME;
        RULE_STAT = CRLExtensionsRuleDataModel.RULE_STAT;
        mHelpToken = CAHELPINDEX;
    }

    public CRLExtensionsInstanceTab(CMSBaseResourceModel model, String dest, String id) {
        super(model,dest,PANEL_NAME);
        Debug.println("CRLExtensionsInstanceTab::CRLExtensionsInstanceTab(<model>,"+dest);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new RuleRuleDataModel();
        mScope = ScopeDef.SC_CRLEXTS_RULES;
        RULE_NAME = CRLExtensionsRuleDataModel.RULE_NAME;
        RULE_STAT = CRLExtensionsRuleDataModel.RULE_STAT;
        mHelpToken = CAHELPINDEX;
        mId = id;
    }


    @Override
    public CMSBaseConfigDialog makeNewConfigDialog(
            NameValuePairs nvp,
            JFrame parent,
            AdminConnection conn,
            String dest)
    {
        if (mId != null && mId.length() > 0)
            return new CRLExtensionsConfigDialog(nvp, parent, conn, dest, mId);
        return new CRLExtensionsConfigDialog(nvp, parent, conn, dest);
    }

	@Override
    public PluginSelectionDialog getPluginSelectionDialog(
            JFrame parent,
            AdminConnection conn,
            String dest,
            CMSPluginInstanceTab pluginType)
    {
        return new CRLExtensionsPluginSelectionDialog(parent, conn, dest, pluginType);
    }


    /**
     * create the user action button panel
     */
    @Override
    protected JPanel createUserButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        mAdd.setEnabled(false);
        mDelete.setEnabled(false);
        mEdit = makeJButton("EDIT");
		JButton[] buttons = {mEdit};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

}

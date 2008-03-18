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
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * RA General Setting
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSRAGeneralPanel extends CMSBaseTab {

    private static String PANEL_NAME = "RAGENERAL";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JCheckBox mRAEnable;
    private JCheckBox mEEEnable;
    private CMSTabPanel mParent;
    private static final String HELPINDEX =
      "configuration-ra-general-help";

    public CMSRAGeneralPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public void init() {
        Debug.println("CMSRAGeneral: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        JPanel adminPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        adminPanel.setLayout(gb1);
        adminPanel.setBorder(makeTitledBorder("PARAMETERS"));

        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(adminPanel, gbc);
        mCenterPanel.add(adminPanel);
        
        CMSAdminUtil.resetGBC(gbc);
        mEEEnable = makeJCheckBox("EE");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mEEEnable, gbc);
        adminPanel.add(mEEEnable);

/*
        CMSAdminUtil.resetGBC(gbc);
        mRAEnable = makeJCheckBox("RA");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mRAEnable, gbc);
        adminPanel.add(mRAEnable);
*/
    
        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_EE_ENABLED, "");
        //nvps.add(Constants.PR_RA_ENABLED, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_RA_ADMIN,
              ScopeDef.SC_GENERAL, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
    }

    protected void populate(NameValuePairs nvps) {
        Debug.println("RA General Received: "+nvps.toString());
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_EE_ENABLED)) {
                mEEEnable.setSelected(getBoolean(nvp.getValue()));
/*
            } else if (name.equals(Constants.PR_RA_ENABLED)) {
                mRAEnable.setSelected(getBoolean(nvp.getValue()));
*/
            }
        }
    }

    private boolean getBoolean(String str) {
        if (str.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        NameValuePairs nvps = new NameValuePairs();

        if (mEEEnable.isSelected())
            nvps.add(Constants.PR_EE_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_EE_ENABLED, Constants.FALSE);

/*
        if (mRAEnable.isSelected())
            nvps.add(Constants.PR_RA_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_RA_ENABLED, Constants.FALSE);
*/

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_RA_ADMIN,
              ScopeDef.SC_GENERAL, Constants.RS_ID_CONFIG, nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        refresh();
        return true;
    }
}

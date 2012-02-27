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
 * KRA General Setting
 *
 * @author Ade Lee
 * @version $Revision: 1211 $, $Date: 2010-08-18 13:15:37 -0400 (Wed, 18 Aug 2010) $
 */
public class CMSEAGeneralPanel extends CMSBaseTab implements ItemListener {

    private static String PANEL_NAME = "EAGENERAL";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JTextField mNumberOfAgentsText;
    private CMSTabPanel mParent;
    private static final String EAHELPINDEX =
      "configuration-ea-general-help";

    public CMSEAGeneralPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = EAHELPINDEX;
    }

    public void init() {
        Debug.println("CMSEAGeneral: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        JPanel agentsPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        agentsPanel.setLayout(gb2);
        agentsPanel.setBorder(makeTitledBorder("AGENTS"));

        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(agentsPanel, gbc);
        mCenterPanel.add(agentsPanel);
        

        CMSAdminUtil.resetGBC(gbc);
        JLabel numberLabel = makeJLabel("NUMBER");
        mNumberOfAgentsText = makeJTextField(30);
        CMSAdminUtil.addEntryField(agentsPanel, numberLabel, mNumberOfAgentsText, gbc);
        
        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS, "1");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_KRA_ADMIN,
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
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS)) {
                mNumberOfAgentsText.setText(value);
            }
        }
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        String numberOfAgents = mNumberOfAgentsText.getText().trim();

        if (numberOfAgents.equals("")) {
            showMessageDialog("BLANKFIELD");
            return false;
        }

        try {
            int num = Integer.parseInt(numberOfAgents);
            if (num < 1) {
                showMessageDialog("NUMBERRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_NO_OF_REQUIRED_RECOVERY_AGENTS,
                numberOfAgents);

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_KRA_ADMIN,
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

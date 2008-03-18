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
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.awt.event.*;

/**
 * KRA scheme management tab
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSKRASchemePanel extends CMSBaseUGTab {
    private static String PANEL_NAME = "SCHEMEMGMT";
    private CMSBaseResourceModel mModel;
    private JButton mSchemeBtn;
    private AdminConnection mAdmin;
    private JLabel mAvailAgentLbl;
    private JLabel mReqAgentLbl;
    private String mAvailAgentStr;
    private String mReqAgentStr;
    private JButton mRefresh, mHelp;
    private static final String HELPINDEX =
      "configuration-kra-schememgt-help";
    private CMSUGTabPanel mParent = null;

    public CMSKRASchemePanel(CMSUGTabPanel parent) {
        super(PANEL_NAME, parent.getResourceModel());
        mModel = parent.getResourceModel();
        mAdmin = mModel.getServerInfo().getAdmin();
        mAvailAgentStr =
          mResource.getString(PANEL_NAME + "_LABEL_AVAILAGENT_LABEL");
        mReqAgentStr =
          mResource.getString(PANEL_NAME + "_LABEL_REQAGENT_LABEL");
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

/*
    public void init() {
        GridBagLayout gbm = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gbm);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        JPanel agentPanel = createAgentPanel();
        gbm.setConstraints(agentPanel, gbc);
        mCenterPanel.add(agentPanel);

        refresh();
    }
*/

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_RECOVERY_N, "");
        nvps.add(Constants.PR_RECOVERY_M, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_KRA_ADMIN,
              ScopeDef.SC_RECOVERY, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            mParent.removeAll();
            //showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
    }

    protected void populate(NameValuePairs nvps) {
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_RECOVERY_N)) {
                mAvailAgentLbl.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_RECOVERY_M)) {
                mReqAgentLbl.setText(nvp.getValue());
            }
        }
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        JButton[] buttons = { mRefresh, mHelp };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        JPanel listPanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        listPanel.setLayout(gb3);

        JPanel agentPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        agentPanel.setLayout(gb);
        agentPanel.setBorder(makeTitledBorder("CURRENT"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        gb3.setConstraints(agentPanel, gbc);
        listPanel.add(agentPanel);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = makeJLabel("REQAGENT");
        mReqAgentLbl= new JLabel("");
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc. insets = new Insets(0,COMPONENT_SPACE,0,0);
        gb.setConstraints(label2, gbc);
        agentPanel.add(label2);

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc. insets = new Insets(0,COMPONENT_SPACE,
                                        0,COMPONENT_SPACE);
        gb.setConstraints(mReqAgentLbl, gbc);
        agentPanel.add(mReqAgentLbl);

        mSchemeBtn = makeJButton("CHANGESCHEME");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mSchemeBtn, gbc);
        agentPanel.add(mSchemeBtn);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = makeJLabel("AVAILAGENT");
        mAvailAgentLbl = new JLabel("");
        gbc.gridheight = gbc.REMAINDER;
        CMSAdminUtil.addEntryField(agentPanel, label1, mAvailAgentLbl, gbc);

        refresh();
        return listPanel;
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mSchemeBtn)) {
            try {
                MNSchemeWizardInfo info = new MNSchemeWizardInfo(mAdmin,
                    Integer.parseInt(mReqAgentLbl.getText()),
                    Integer.parseInt(mAvailAgentLbl.getText()));
                MNSchemeWizard wizard = new MNSchemeWizard(mModel.getFrame(), info);
            } catch(NumberFormatException ex) {
                Debug.println("CMSKRASchemePanel: MN not intereger "+ex.toString());
                showErrorDialog(mResource.getString("SCHEMEMGMT_DIALOG_MNFORMAT_MESSAGE"));
            }
            refresh();
        } else if (e.getSource().equals(mRefresh)) {
            refresh();
        } else if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
    }

    public void mouseClicked(MouseEvent e) {
    }

}


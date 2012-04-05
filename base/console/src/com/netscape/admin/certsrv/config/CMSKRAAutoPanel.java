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
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * KRA recovery management tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSKRAAutoPanel extends CMSBaseUGTab {
    private static String PANEL_NAME = "AUTORECOVERYMGMT";
    private CMSBaseResourceModel mModel;
    private JButton mEnableAuto;
    private AdminConnection mAdmin;
    private String mEnableLabel;
    private String mEnableTTip;
    private String mDisableLabel;
    private String mDisableTTip;
    private JButton mRefresh, mHelp;
    private JLabel mStatus;
    private String mEnableStatus;
    private String mEnableStatusTTip;
    private String mDisableStatus;
    private String mDisableStatusTTip;
    private static final String HELPINDEX =
      "configuration-kra-autorecovery-help";

    public CMSKRAAutoPanel(CMSUGTabPanel parent) {
        super(PANEL_NAME, parent.getResourceModel());
        mModel = parent.getResourceModel();
        mAdmin = mModel.getServerInfo().getAdmin();
        mDisableTTip = mResource.getString(PANEL_NAME + "_BUTTON_"+
          "DISABLEAUTO_TTIP");
        mDisableLabel = mResource.getString(PANEL_NAME + "_BUTTON_"+
          "DISABLEAUTO_LABEL");
        mEnableTTip = mResource.getString(PANEL_NAME + "_BUTTON_"+
          "ENABLEAUTO_TTIP");
        mEnableLabel = mResource.getString(PANEL_NAME + "_BUTTON_"+
          "ENABLEAUTO_LABEL");
        mEnableStatus = mResource.getString(PANEL_NAME + "_LABEL_"+
          "ENABLESTATUS_LABEL");
        mEnableStatusTTip = mResource.getString(PANEL_NAME + "_LABEL_"+
          "ENABLESTATUS_TTIP");
        mDisableStatus = mResource.getString(PANEL_NAME + "_LABEL_"+
          "DISABLESTATUS_LABEL");
        mDisableStatusTTip = mResource.getString(PANEL_NAME + "_LABEL_"+
          "DISABLESTATUS_TTIP");
        mHelpToken = HELPINDEX;
    }

    protected JPanel createListPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb3);

        JPanel autoPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        autoPanel.setLayout(gb);
        autoPanel.setBorder(makeTitledBorder("AUTO"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        gb3.setConstraints(autoPanel, gbc);
        mainPanel.add(autoPanel);

        // Auto recovery
        CMSAdminUtil.resetGBC(gbc);
        JLabel autoLabel = makeJLabel("ENABLEAUTO");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(autoLabel, gbc);
        autoPanel.add(autoLabel);

        // labels
        CMSAdminUtil.resetGBC(gbc);
        mStatus = makeJLabel("ENABLESTATUS");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(mStatus, gbc);
        autoPanel.add(mStatus);

        CMSAdminUtil.resetGBC(gbc);
        mEnableAuto = makeJButton("DISABLEAUTO");
        mEnableAuto.setPreferredSize(new Dimension(78, 23));
        mEnableAuto.setActionCommand("autoButton");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(mEnableAuto, gbc);
        autoPanel.add(mEnableAuto);

        refresh();
        return mainPanel;
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        //JButton[] buttons = { mRefresh, mHelp };
        JButton[] buttons = { mRefresh };
        return makeJButtonPanel(buttons, true);
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_AUTO_RECOVERY_ON, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_KRA_ADMIN,
              ScopeDef.SC_AUTO_RECOVERY, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
        }
        mModel.progressStop();
    }

    protected void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_AUTO_RECOVERY_ON)) {
                if (value.equals(Constants.TRUE)) {
                    setStatus(true);
                    //mEnableAuto.setText(mDisableLabel);
                    //mEnableAuto.setToolTipText(mDisableTTip);
                } else {
                    setStatus(false);
                    //mEnableAuto.setText(mEnableLabel);
                    //mEnableAuto.setToolTipText(mEnableTTip);
                }
            }
        }
    }

    private void setStatus(boolean enabled) {
        if (enabled) {
            mEnableAuto.setText(mDisableLabel);
            mEnableAuto.setToolTipText(mDisableTTip);
            mStatus.setText(mEnableStatus);
            mStatus.setToolTipText(mEnableStatusTTip);
        } else {
            mEnableAuto.setText(mEnableLabel);
            mEnableAuto.setToolTipText(mEnableTTip);
            mStatus.setText(mDisableStatus);
            mStatus.setToolTipText(mDisableStatusTTip);
        }
    }

    public void actionPerformed(ActionEvent e) {

        if (e.getActionCommand().equals("autoButton")) {
            String text = mEnableAuto.getText();
            if (text.equals(mEnableLabel)) {
                JDialog enableDialog = new CMSAutoRecovery(mModel.getFrame(),
                  mAdmin, mEnableAuto);
            } else {
                mModel.progressStart();
                NameValuePairs nvps = new NameValuePairs();
                nvps.put(Constants.PR_AUTO_RECOVERY_ON, Constants.FALSE);
                try {
                    mAdmin.modify(DestDef.DEST_KRA_ADMIN,
                      ScopeDef.SC_AUTO_RECOVERY, Constants.RS_ID_CONFIG, nvps);
                    //mEnableAuto.setText(mEnableLabel);
                    //mEnableAuto.setToolTipText(mEnableTTip);
                } catch (EAdminException ex) {
                    showErrorDialog(ex.toString());
                }
                mModel.progressStop();
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


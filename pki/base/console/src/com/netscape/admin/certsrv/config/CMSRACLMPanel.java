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
 * RA CLM Setting
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSRACLMPanel extends CMSBaseTab {

    private static String PANEL_NAME = "RACLM";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JCheckBox mRenewEnable;
    private JTextField mValidText;
    private JTextField mEmailText;
    private JCheckBox mNotifyEnable;
    private JTextField mNotifiedText;
    private JTextField mIntervalText;
    private Color mActiveColor;
    private CMSTabPanel mParent;
    private static final String HELPINDEX = 
      "configuration-ra-clm-help";

    public CMSRACLMPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public void init() {
        Debug.println("CMSRACLMPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mRenewEnable = makeJCheckBox("RENEWENABLED");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mRenewEnable, gbc);
        mCenterPanel.add(mRenewEnable);

        JPanel adminPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        adminPanel.setLayout(gb1);
        adminPanel.setBorder(makeTitledBorder("CLMRENEWAL"));

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
        JLabel validLbl = makeJLabel("VALID");
        mValidText = makeJTextField(4);
        mActiveColor = mValidText.getBackground();
        JLabel day1Lbl = makeJLabel("DAYS");
        CMSAdminUtil.addEntryField(adminPanel, validLbl, mValidText, 
          day1Lbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        //JLabel dummy2 = new JLabel("");
        mNotifyEnable = makeJCheckBox("NOTIFIED");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gb1.setConstraints(mNotifyEnable, gbc);
        adminPanel.add(mNotifyEnable);

        //CMSAdminUtil.addEntryField(adminPanel, dummy2, mNotifyEnable, gbc);

        JPanel subPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        subPanel.setLayout(gb2);
        subPanel.setBorder(makeTitledBorder("CLMRENEWALNOTIFY"));

        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(subPanel, gbc);
        adminPanel.add(subPanel);

        CMSAdminUtil.resetGBC(gbc);
        JLabel emailLbl = makeJLabel("EMAIL");
        mEmailText = makeJTextField(30);
        CMSAdminUtil.addEntryField(subPanel, emailLbl, mEmailText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel numNotifyLbl = makeJLabel("NUMNOTIFIED");
        mNotifiedText = makeJTextField(4);
        CMSAdminUtil.addEntryField(subPanel, numNotifyLbl, mNotifiedText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel intervalLbl = makeJLabel("INTERVAL");
        mIntervalText = makeJTextField(4);
        JLabel day2Lbl = makeJLabel("DAYS");
        CMSAdminUtil.addEntryField(subPanel, intervalLbl, mIntervalText, 
          day2Lbl, gbc);

        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_RENEWAL_ENABLED, "");
        nvps.add(Constants.PR_RENEWAL_VALIDITY, "");
        nvps.add(Constants.PR_RENEWAL_EMAIL, "");
        nvps.add(Constants.PR_RENEWAL_EXPIREDNOTIFIEDENABLED, "");
        nvps.add(Constants.PR_RENEWAL_NUMNOTIFICATION, "");
        nvps.add(Constants.PR_RENEWAL_INTERVAL, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_RA_ADMIN,
              ScopeDef.SC_CLM, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    protected void populate(NameValuePairs nvps) {
        boolean renewalEnabled = false;
        boolean notificationEnabled = false;
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_RENEWAL_ENABLED)) {
                renewalEnabled = getBoolean(nvp.getValue());
                mRenewEnable.setSelected(renewalEnabled);
            } else if (name.equals(Constants.PR_RENEWAL_EXPIREDNOTIFIEDENABLED)) {
                notificationEnabled = getBoolean(nvp.getValue());
                mNotifyEnable.setSelected(notificationEnabled);
            } else if (name.equals(Constants.PR_RENEWAL_VALIDITY)) {
                mValidText.setText(nvp.getValue());                
            } else if (name.equals(Constants.PR_RENEWAL_EMAIL)) {   
                mEmailText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_RENEWAL_NUMNOTIFICATION)) {
                mNotifiedText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_RENEWAL_INTERVAL)) {
                mIntervalText.setText(nvp.getValue());
            }
        }

        if (renewalEnabled) {
            enableRenewal(renewalEnabled, mActiveColor);
            if (notificationEnabled)
                enableNotification(notificationEnabled, mActiveColor);
            else
                enableNotification(notificationEnabled, getBackground());
        } else {
            enableRenewal(renewalEnabled, getBackground());
            enableNotification(renewalEnabled, getBackground());
        }
    }

    private boolean getBoolean(String str) {
        if (str.equals(Constants.TRUE))
            return true;
        return false;
    }

    private void enableRenewal(boolean renewalEnabled, boolean notificationEnabled) {

        if (renewalEnabled) {
            enableRenewal(renewalEnabled, mActiveColor);
            if (notificationEnabled)
                enableNotification(notificationEnabled, mActiveColor);
            else
                enableNotification(notificationEnabled, getBackground());
        } else {
            enableRenewal(renewalEnabled, getBackground());
            enableNotification(renewalEnabled, getBackground());
        }
    }

    private void enableRenewal(boolean enable, Color color) {
        mValidText.setEnabled(enable);
        mValidText.setEditable(enable);
        mValidText.setBackground(color);
        mNotifyEnable.setEnabled(enable);        
        mNotifyEnable.setBackground(color);
        //enableNotification(enable, color);
    }

    private void enableNotification(boolean enable, Color color) {
        mEmailText.setEnabled(enable);
        mEmailText.setEditable(enable);
        mEmailText.setBackground(color);
        mNotifiedText.setEnabled(enable);
        mNotifiedText.setEditable(enable);
        mNotifiedText.setBackground(color);
        mIntervalText.setEnabled(enable);
        mIntervalText.setEditable(enable);
        mIntervalText.setBackground(color);
        invalidate();
        validate();
        repaint(1);
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (e.getSource().equals(mRenewEnable) || 
            e.getSource().equals(mNotifyEnable)) {
            enableRenewal(mRenewEnable.isSelected(), 
              mNotifyEnable.isSelected());
        }
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        NameValuePairs nvps = new NameValuePairs();
        if (mRenewEnable.isSelected()) {
            nvps.add(Constants.PR_RENEWAL_ENABLED, Constants.TRUE);
            String validStr = mValidText.getText();
            try {
                int num = Integer.parseInt(validStr);
            } catch (NumberFormatException e) {
                showMessageDialog("NUMBERFORMAT");
                return false;
            }
            nvps.add(Constants.PR_RENEWAL_VALIDITY, validStr);
        
            if (mNotifyEnable.isSelected()) {
                nvps.add(Constants.PR_RENEWAL_EXPIREDNOTIFIEDENABLED, 
                  Constants.TRUE);
                nvps.add(Constants.PR_RENEWAL_EMAIL, mEmailText.getText());
                String numStr = mNotifiedText.getText();
                String intervalStr = mIntervalText.getText();

                try {
                    int num1 = Integer.parseInt(numStr);
                    int num2 = Integer.parseInt(intervalStr);
                } catch (NumberFormatException ex) {
                    showMessageDialog("NUMBERFORMAT");
                    return false;
                }

                nvps.add(Constants.PR_RENEWAL_NUMNOTIFICATION, numStr);
                nvps.add(Constants.PR_RENEWAL_INTERVAL, intervalStr);
            } else {
                nvps.add(Constants.PR_RENEWAL_EXPIREDNOTIFIEDENABLED, 
                  Constants.FALSE);
            }
        } else {
            nvps.add(Constants.PR_RENEWAL_ENABLED, Constants.FALSE);
        }

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_RA_ADMIN,
              ScopeDef.SC_CLM, Constants.RS_ID_CONFIG, nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }
        mModel.progressStop();
        clearDirtyFlag();
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

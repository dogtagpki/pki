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

import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.ug.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * LDAP server setting tab
 *
 * @author Ade Lee
 * @version $Revision: 1211 $, $Date: 2010-08-18 13:15:37 -0400 (Wed, 18 Aug 2010) $
 */
public class GeneralLogPanel extends CMSBaseTab {

    private static String PANEL_NAME = "GENERALLOG";
    private static final String HELPINDEX = 
      "configuration-general-logs-settings-help";
    private JCheckBox mEnable;
    private Color mActiveColor;
    private JLabel mLevelLabel;
    private JTextField mLevelText;
    private JCheckBox mShowCaller;

    protected AdminConnection mAdmin;
    protected CMSBaseResourceModel mModel;
    private String mServletName;
    private CMSTabPanel mParent;

    public GeneralLogPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mHelpToken = HELPINDEX;
        mServletName = DestDef.DEST_LOG_ADMIN;
        mModel = parent.getResourceModel();
        mParent = parent;
    }

    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel serverInfo = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);

        //add the enable checkbox
        mEnable = makeJCheckBox("ENABLE");
        mEnable.setSelected(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,
                                DIFFERENT_COMPONENT_SPACE,
                                0,
                                DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(mEnable, gbc);
                mCenterPanel.add(mEnable);

        //add the debug properties panel
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(serverInfo, gbc);
        mCenterPanel.add(serverInfo);

        GridBagLayout gb1 = new GridBagLayout();
        serverInfo.setLayout(gb1);
                serverInfo.setBorder(makeTitledBorder("DEBUG"));

        // add frequency label and text field
        CMSAdminUtil.resetGBC(gbc);
        mLevelLabel = makeJLabel("LEVEL");
        mLevelText = makeJTextField(30);
        mActiveColor = mLevelText.getBackground();
        CMSAdminUtil.addEntryField(serverInfo,
            mLevelLabel, mLevelText, gbc);

        // add show caller checkbox
        /*
        CMSAdminUtil.resetGBC(gbc);
        mShowCaller = makeJCheckBox("SHOWCALLER");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,0,COMPONENT_SPACE);
        gb1.setConstraints(mShowCaller, gbc);
        serverInfo.add(mShowCaller);
        */
        refresh();
    }


    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_DEBUG_LOG_ENABLE, "true");
        nvps.add(Constants.PR_DEBUG_LOG_LEVEL, "0");
        /*nvps.add(Constants.PR_DEBUG_LOG_SHOWCALLER, ""); */

        try {
            NameValuePairs val = mAdmin.read(mServletName,
              ScopeDef.SC_GENERAL, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    private void enableFields(boolean enable, Color color) {
        mLevelText.setEnabled(enable);
        mLevelText.setEditable(enable);
        mLevelText.setBackground(color);
        mLevelLabel.setEnabled(enable);
        mLevelLabel.setBackground(color);

        mLevelLabel.invalidate();
        mLevelLabel.validate();
        mLevelLabel.repaint(1);
    }

    protected void populate(NameValuePairs nvps) {
        String version = "";
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_DEBUG_LOG_ENABLE)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mEnable.setSelected(true);
                else
                    mEnable.setSelected(false);
            } else if (name.equals(Constants.PR_DEBUG_LOG_LEVEL)) {
                mLevelText.setText(nvp.getValue());
            } 

            /* else if (name.equals(Constants.PR_DEBUG_LOG_SHOWCALLER)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mShowCaller.setSelected(true);
                else
                    mShowCaller.setSelected(false);
            } */

        }

        if (mEnable.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());

    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (mEnable.isSelected()) {
            enableFields(true, mActiveColor);
        } else {
            enableFields(false, getBackground());
        }
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        // check blank fields
        String level = mLevelText.getText().trim();

        if (mEnable.isSelected() && level.equals(""))  {
            showMessageDialog("BLANKFIELD");
            return false;
        }

        try {
            int num = Integer.parseInt(level);
            if (num < 0) {
                showMessageDialog("LEVELRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_DEBUG_LOG_LEVEL, level);

        /*
        if (mShowCaller.isSelected())
            nvps.add(Constants.PR_DEBUG_LOG_SHOWCALLER, Constants.TRUE);
        else
            nvps.add(Constants.PR_DEBUG_LOG_SHOWCALLER, Constants.FALSE);
        */

        if (mEnable.isSelected())
            nvps.add(Constants.PR_DEBUG_LOG_ENABLE, Constants.TRUE);
        else
            nvps.add(Constants.PR_DEBUG_LOG_ENABLE, Constants.FALSE);

        mModel.progressStart();
        try {
            mAdmin.modify(mServletName, ScopeDef.SC_GENERAL,
              Constants.RS_ID_CONFIG, nvps, false);
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


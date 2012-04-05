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
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * SNMP setting tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSSNMPPanel extends CMSBaseTab {
    private static String PANEL_NAME = "SNMPSETTING";
    private Color mActiveColor;
    private JButton mOnB;
    private JButton mOffB;
    private JCheckBox mEnable;
    private JTextField mHostNameText;
    private JTextField mPortText;
    private JTextField mDescText;
    private JTextField mOrgnText;
    private JTextField mLocText;
    private JTextField mContactText;
    private AdminConnection mAdmin;
    private CMSBaseResourceModel mModel;
    private CMSTabPanel mParent;
    private JLabel mHostLabel;
    private JLabel mPortLabel;
    private JLabel mDescLabel;
    private JLabel mOrgnLabel;
    private JLabel mLocLabel;
    private JLabel mContactLabel;
    private static final String HELPINDEX =
     "configuration-system-snmp-help";

    public CMSSNMPPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public void init() {
        Debug.println("SNMPPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel snmpInfo = new JPanel();
        snmpInfo.setBorder(CMSAdminUtil.makeEtchedBorder());
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        mEnable = makeJCheckBox("ENABLE");
        mEnable.setActionCommand("enable");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mEnable, gbc);
        mCenterPanel.add(mEnable);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(snmpInfo, gbc);
        mCenterPanel.add(snmpInfo);

        mOnB = makeJButton("ON");
        mOffB = makeJButton("OFF");
        JButton[] bArray = {mOnB, mOffB};
        JPanel buttonPanel = CMSAdminUtil.makeJButtonPanel(bArray);

        GridBagLayout gb1 = new GridBagLayout();
        snmpInfo.setLayout(gb1);

        // add host name label and text field
        CMSAdminUtil.resetGBC(gbc);
        mHostLabel = makeJLabel("HOST");
        mHostNameText = makeJTextField(30);
        mActiveColor = mHostNameText.getBackground();
        CMSAdminUtil.addEntryField(snmpInfo, mHostLabel, mHostNameText, gbc);

        // add port label and text field
        CMSAdminUtil.resetGBC(gbc);
        mPortLabel = makeJLabel("PORT");
        mPortText = makeJTextField(30);
        CMSAdminUtil.addEntryField(snmpInfo, mPortLabel, mPortText, gbc);

        // add description label and text field
        CMSAdminUtil.resetGBC(gbc);
        mDescLabel = makeJLabel("DESC");
        mDescText = makeJTextField(30);
        CMSAdminUtil.addEntryField(snmpInfo, mDescLabel, mDescText, gbc);

        // add organization label and text field
        CMSAdminUtil.resetGBC(gbc);
        mOrgnLabel = makeJLabel("ORGN");
        mOrgnText = makeJTextField(30);
        CMSAdminUtil.addEntryField(snmpInfo, mOrgnLabel, mOrgnText, gbc);

        // add location label and text field
        CMSAdminUtil.resetGBC(gbc);
        mLocLabel = makeJLabel("LOC");
        mLocText = makeJTextField(30);
        CMSAdminUtil.addEntryField(snmpInfo, mLocLabel, mLocText, gbc);

        // add contact label and text field
        CMSAdminUtil.resetGBC(gbc);
        mContactLabel = makeJLabel("CONTACT");
        mContactText = makeJTextField(30);
        CMSAdminUtil.addEntryField(snmpInfo, mContactLabel, mContactText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gb1.setConstraints(buttonPanel, gbc);
        snmpInfo.add(buttonPanel);

        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_SNMP_ENABLED, "");
        nvps.put(Constants.PR_SNMP_MASTER_HOST, "");
        nvps.put(Constants.PR_SNMP_MASTER_PORT, "");
        nvps.put(Constants.PR_SNMP_DESC, "");
        nvps.put(Constants.PR_SNMP_ORGN, "");
        nvps.put(Constants.PR_SNMP_LOC, "");
        nvps.put(Constants.PR_SNMP_CONTACT, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SNMP, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    private void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_SNMP_ENABLED)) {
                mEnable.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_SNMP_MASTER_HOST)) {
                mHostNameText.setText(value);
            } else if (name.equals(Constants.PR_SNMP_MASTER_PORT)) {
                mPortText.setText(value);
            } else if (name.equals(Constants.PR_SNMP_DESC)) {
                mDescText.setText(value);
            } else if (name.equals(Constants.PR_SNMP_ORGN)) {
                mOrgnText.setText(value);
            } else if (name.equals(Constants.PR_SNMP_LOC)) {
                mLocText.setText(value);
            } else if (name.equals(Constants.PR_SNMP_CONTACT)) {
                mContactText.setText(value);
            }
        }

        if (mEnable.isSelected())
            enableTextField(true, mActiveColor);
        else
            enableTextField(false, getBackground());
    }

    public boolean getBoolean(String value) {
        if (value.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (e.getActionCommand().equals("enable")) {
            if (mEnable.isSelected()) {
                enableTextField(true, mActiveColor);
            } else {
                enableTextField(false, getBackground());
            }
        }
    }

    private void enableTextField(boolean enable, Color color) {
        mHostNameText.setEnabled(enable);
        mHostNameText.setEditable(enable);
        mHostNameText.setBackground(color);
        mHostLabel.setEnabled(enable);
        mPortText.setEnabled(enable);
        mPortText.setEditable(enable);
        mPortText.setBackground(color);
        mPortLabel.setEnabled(enable);
        mDescText.setEnabled(enable);
        mDescText.setEditable(enable);
        mDescText.setBackground(color);
        mDescLabel.setEnabled(enable);
        mOrgnText.setEnabled(enable);
        mOrgnText.setEditable(enable);
        mOrgnText.setBackground(color);
        mOrgnLabel.setEnabled(enable);
        mLocText.setEnabled(enable);
        mLocText.setEditable(enable);
        mLocText.setBackground(color);
        mLocLabel.setEnabled(enable);
        mContactText.setEnabled(enable);
        mContactText.setEditable(enable);
        mContactText.setBackground(color);
        mContactLabel.setEnabled(enable);
        mOnB.setEnabled(enable);
        mOffB.setEnabled(enable);
        invalidate();
        validate();
        repaint(1);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        String port = mPortText.getText().trim();

        try {
            Integer num = new Integer(port);
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        if (mEnable.isSelected())
            nvps.put(Constants.PR_SNMP_ENABLED, Constants.TRUE);
        else
            nvps.put(Constants.PR_SNMP_ENABLED, Constants.FALSE);

        nvps.put(Constants.PR_SNMP_MASTER_HOST, mHostNameText.getText().trim());
        nvps.put(Constants.PR_SNMP_MASTER_PORT, port);
        nvps.put(Constants.PR_SNMP_DESC, mDescText.getText().trim());
        nvps.put(Constants.PR_SNMP_ORGN, mOrgnText.getText().trim());
        nvps.put(Constants.PR_SNMP_LOC, mLocText.getText().trim());
        nvps.put(Constants.PR_SNMP_CONTACT, mContactText.getText().trim());

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SNMP, Constants.RS_ID_CONFIG, nvps);
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

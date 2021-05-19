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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

/**
 * SMTP setting tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSSMTPPanel extends CMSBaseTab {
    private static String PANEL_NAME = "SMTPSETTING";
    private JTextField mServerText;
    private JTextField mPortText;
    private AdminConnection mAdmin;
    private CMSBaseResourceModel mModel;
    private CMSTabPanel mParent;
    private static final String HELPINDEX =
      "configuration-system-smtp-help";

    public CMSSMTPPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    @Override
    public void init() {
        Debug.println("SMTPPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel smtpInfo = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(smtpInfo, gbc);
        mCenterPanel.add(smtpInfo);

        GridBagLayout gb1 = new GridBagLayout();
        smtpInfo.setLayout(gb1);

        // add server name label and text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel serverLabel = makeJLabel("SERVER");
        mServerText = makeJTextField(30);
        CMSAdminUtil.addEntryField(smtpInfo, serverLabel, mServerText, gbc);

        // add port number label and text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel portLabel = makeJLabel("PORT");
        mPortText = makeJTextField(30);
        CMSAdminUtil.addEntryField(smtpInfo, portLabel, mPortText, gbc);

        refresh();
    }

    @Override
    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_SERVER_NAME, "");
        nvps.put(Constants.PR_PORT, "");
        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SMTP, Constants.RS_ID_CONFIG, nvps);

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
            if (name.equals(Constants.PR_SERVER_NAME)) {
                mServerText.setText(value);
            } else if (name.equals(Constants.PR_PORT)) {
                mPortText.setText(value);
            }
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean applyCallback() {
        // check blank field
        if (mServerText.getText().trim().equals("")) {
            showMessageDialog("BLANKFIELD");
            return false;
        }

        String port = mPortText.getText().trim();
        try {
            int num = Integer.parseInt(port);
            if (num <= 0) {
                showMessageDialog("OUTOFRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_SERVER_NAME, mServerText.getText().trim());
        nvps.put(Constants.PR_PORT, port);
        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SMTP, Constants.RS_ID_CONFIG, nvps);
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
    @Override
    public boolean resetCallback() {
        refresh();
        return true;
    }
}


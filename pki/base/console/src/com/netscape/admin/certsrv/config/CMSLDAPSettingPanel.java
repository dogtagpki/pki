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
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * LDAP server setting tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSLDAPSettingPanel extends CMSBaseTab {

    private static String PANEL_NAME = "LDAPSETTING";
    private static final String HELPINDEX = 
      "configuration-database-settings-help";
    private JTextField mHostNameText;
    private JTextField mPortText;
    private JTextField mBindAsText;
    private JPasswordField mPasswordText;
    private JPasswordField mPasswordAgainText;
    private JCheckBox mEnable;
    private Color mActiveColor;
    protected AdminConnection mAdmin;
    protected CMSBaseResourceModel mModel;
    private String mServletName;
    private CMSTabPanel mParent;
    private static final int MAX_PORT = 65535;
    //private JComboBox mVersionBox;

    public CMSLDAPSettingPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mHelpToken = HELPINDEX;
        mServletName = getServletName(PANEL_NAME);
        mModel = parent.getResourceModel();
        mParent = parent;
    }

    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel serverInfo = new JPanel();
        serverInfo.setBorder(makeTitledBorder("SETTING"));
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);

        //add the destination panel
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

        // add host name label and text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel hostLabel = makeJLabel("HOST");
        mHostNameText = makeJTextField(30);
        mActiveColor = mHostNameText.getBackground();
        CMSAdminUtil.addEntryField(serverInfo, hostLabel, mHostNameText, gbc);

        // add port number label
        CMSAdminUtil.resetGBC(gbc);
        JLabel portLabel = makeJLabel("PORT");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        gb1.setConstraints(portLabel, gbc);
        serverInfo.add(portLabel);

        // add port number text field
        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        //gbc.weightx = 0.0;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gb1.setConstraints(mPortText, gbc);
        serverInfo.add(mPortText);

        // add check box
/*
        CMSAdminUtil.resetGBC(gbc);
        mSecurePort = makeJCheckBox("SECUREPORT");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,0,COMPONENT_SPACE);
        gb1.setConstraints(mSecurePort, gbc);
        serverInfo.add(mSecurePort);
*/

        // add base DN label and text field
/*
        CMSAdminUtil.resetGBC(gbc);
        JLabel baseDNLabel = makeJLabel("BASEDN");
        mBaseDNText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, baseDNLabel, mBaseDNText, gbc);
*/

        // add bind as label and text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel bindAsLabel = makeJLabel("BINDAS");
        mBindAsText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, bindAsLabel, mBindAsText, gbc);

        // add password label and text field
/*
        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordLabel = makeJLabel("PWD");
        mPasswordText = makeJPasswordField(20);
        CMSAdminUtil.addEntryField(serverInfo, passwordLabel, mPasswordText, gbc);
*/

        // add password again label and text field
/*
        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordAgainLabel = makeJLabel("PWDAGAIN");
        mPasswordAgainText = makeJPasswordField(30);
        CMSAdminUtil.addEntryField(serverInfo, passwordAgainLabel,
          mPasswordAgainText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel versionLabel = makeJLabel("VERSION");
        mVersionBox = makeJComboBox("VERSION");
        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.addEntryField(serverInfo, versionLabel, mVersionBox,
          dummy, gbc);
*/

        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_HOST_NAME, "");
        nvps.add(Constants.PR_LDAP_PORT, "");
        //nvps.add(Constants.PR_SECURE_PORT_ENABLED, "");
        //nvps.add(Constants.PR_BASE_DN, "");
        nvps.add(Constants.PR_BIND_DN, "");
        nvps.add(Constants.PR_LDAP_VERSION, "");

        try {
            NameValuePairs val = mAdmin.read(mServletName,
              ScopeDef.SC_LDAP, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    protected String getServletName(String panelName) {
        if (panelName.equals("LDAPSETTING"))
            return DestDef.DEST_SERVER_ADMIN;
        else if (panelName.equals("CALDAPSETTING"))
            return DestDef.DEST_CA_ADMIN;
        return DestDef.DEST_RA_ADMIN;
    }

    protected void populate(NameValuePairs nvps) {
        String version = "";
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_HOST_NAME)) {
                mHostNameText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_LDAP_PORT)) {
                mPortText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_SECURE_PORT_ENABLED)) {
/*
                if (nvp.getValue().equals(Constants.TRUE))
                    mSecurePort.setSelected(true);
                else
                    mSecurePort.setSelected(false);
*/
            } else if (name.equals(Constants.PR_BASE_DN)) {
                //mBaseDNText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_BIND_DN)) {
                mBindAsText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_ENABLE)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mEnable.setSelected(true);
                else
                    mEnable.setSelected(false);
            } else if (name.equals(Constants.PR_LDAP_VERSION)) {
                version = nvp.getValue();
            }
        }

/*
        if (version.equals(""))
            mVersionBox.setSelectedIndex(1);
        else
            mVersionBox.setSelectedItem(version);
*/
        //mPasswordText.setText("");
        //mPasswordAgainText.setText("");
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        // check blank fields
        String host = mHostNameText.getText().trim();
        String port = mPortText.getText().trim();
        //String baseDN = mBaseDNText.getText().trim();
        String bindAs = mBindAsText.getText().trim();

        //if (host.equals("") || port.equals("") || baseDN.equals("") ||
        //  bindAs.equals("")) {
        if (host.equals("") || port.equals("") || bindAs.equals("")) {
            showMessageDialog("BLANKFIELD");
            return false;
        }

        try {
            int num = Integer.parseInt(port);
            if (num <= 0 || num > MAX_PORT) {
                showMessageDialog("PORTRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_HOST_NAME, host);
        nvps.add(Constants.PR_LDAP_PORT, port);
        //nvps.add(Constants.PR_BASE_DN, baseDN);
        nvps.add(Constants.PR_BIND_DN, bindAs);
/*
        nvps.add(Constants.PR_LDAP_VERSION, 
          (String)mVersionBox.getSelectedItem());
*/

/*
        if (mSecurePort.isSelected())
            nvps.add(Constants.PR_SECURE_PORT_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_SECURE_PORT_ENABLED, Constants.FALSE);
*/

/*
        String passwd = mPasswordText.getText();
        String passwdagain = mPasswordAgainText.getText();

        if (!passwd.equals("") && !passwdagain.equals("")) {
           if (passwd.equals(passwdagain)) {
               nvps.add(Constants.PR_BIND_PASSWD, passwd);
           } else {
               showMessageDialog("UNMATCHEDPASSWD");
               return false;
           }
        } else if (((!passwd.equals("")) && passwdagain.equals("")) ||
          ((!passwd.equals("")) && passwdagain.equals(""))) {
            showMessageDialog("UNMATCHEDPASSWD");
            return false;
        }
*/

        mModel.progressStart();
        try {
            mAdmin.modify(mServletName, ScopeDef.SC_LDAP,
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


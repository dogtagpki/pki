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
import java.awt.Insets;
import java.awt.event.ActionEvent;

import javax.swing.JCheckBox;
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
    private JTextField mMaxConnsText;
    private JTextField mMinConnsText;
    private JCheckBox mEnable;
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

    @Override
    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel serverInfo = new JPanel();
        serverInfo.setBorder(makeTitledBorder("SETTING"));
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);

        //add the destination panel
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
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
        CMSAdminUtil.addEntryField(serverInfo, hostLabel, mHostNameText, gbc);

        // add port number label
        CMSAdminUtil.resetGBC(gbc);
        JLabel portLabel = makeJLabel("PORT");
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        gb1.setConstraints(portLabel, gbc);
        serverInfo.add(portLabel);

        // add port number text field
        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        //gbc.weightx = 0.0;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
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

        // add maxconns label text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel maxConnsLabel = makeJLabel("MAXCONNS");
        mMaxConnsText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, maxConnsLabel, mMaxConnsText, gbc);

        // add maxconns label text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel minConnsLabel = makeJLabel("MINCONNS");
        mMinConnsText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, minConnsLabel, mMinConnsText, gbc);

        refresh();
    }

    @Override
    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_HOST_NAME, "");
        nvps.put(Constants.PR_LDAP_PORT, "");
        //nvps.add(Constants.PR_SECURE_PORT_ENABLED, "");
        //nvps.add(Constants.PR_BASE_DN, "");
        nvps.put(Constants.PR_BIND_DN, "");
        nvps.put(Constants.PR_LDAP_VERSION, "");
        nvps.put(Constants.PR_LDAP_MAX_CONNS, "");
        nvps.put(Constants.PR_LDAP_MIN_CONNS, "");

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
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_HOST_NAME)) {
                mHostNameText.setText(value);
            } else if (name.equals(Constants.PR_LDAP_PORT)) {
                mPortText.setText(value);
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
                mBindAsText.setText(value);
            } else if (name.equals(Constants.PR_ENABLE)) {
                if (value.equals(Constants.TRUE))
                    mEnable.setSelected(true);
                else
                    mEnable.setSelected(false);
            } else if (name.equals(Constants.PR_LDAP_VERSION)) {
                version = value;
            } else if (name.equals(Constants.PR_LDAP_MIN_CONNS)) {
                mMinConnsText.setText(value);
            } else if (name.equals(Constants.PR_LDAP_MAX_CONNS)) {
                mMaxConnsText.setText(value);
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
        // check blank fields
        String host = mHostNameText.getText().trim();
        String port = mPortText.getText().trim();
        //String baseDN = mBaseDNText.getText().trim();
        String bindAs = mBindAsText.getText().trim();
        String maxConns = mMaxConnsText.getText().trim();
        String minConns = mMinConnsText.getText().trim();

        //if (host.equals("") || port.equals("") || baseDN.equals("") ||
        //  bindAs.equals("")) {
        if (host.equals("") || port.equals("") || bindAs.equals("") || maxConns.equals("") || minConns.equals("")) {
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

        try {
            int max = Integer.parseInt(maxConns);
            int min = Integer.parseInt(minConns);
            if ((max < min) || (max <0) || (min <0)) {
                showMessageDialog("MAXMINRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("MAXMINNUMBERFORMAT");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_HOST_NAME, host);
        nvps.put(Constants.PR_LDAP_PORT, port);
        //nvps.add(Constants.PR_BASE_DN, baseDN);
        nvps.put(Constants.PR_BIND_DN, bindAs);
        nvps.put(Constants.PR_LDAP_MAX_CONNS, maxConns);
        nvps.put(Constants.PR_LDAP_MIN_CONNS, minConns);
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
    @Override
    public boolean resetCallback() {
        refresh();
        return true;
    }
}


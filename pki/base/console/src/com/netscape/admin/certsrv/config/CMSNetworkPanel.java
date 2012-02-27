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
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleInfo;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;
import netscape.ldap.*;

/**
 * Network Connection Setting Tab to be displayed at the right hand side
 *
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSNetworkPanel extends CMSBaseTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private final static String PANEL_NAME = "NETWORK";
    private final static String DISABLED = "-1";

    private static final int MAX_PORT = 65535;
    private static final int MIN_PORT = 1;

    private Color mActiveColor; 

    // TextField for port
    private JTextField mAdminSSLPortText;
    private JTextField mAgentSSLPortText;
    private JTextField mGatewayPortText;
    private JTextField mGatewaySSLPortText;

    // TextField for Backlog
    private JTextField mAdminSSLBacklogText;
    private JTextField mAgentSSLBacklogText;
    private JTextField mGatewayBacklogText;
    private JTextField mGatewaySSLBacklogText;

    // Label for EE port
    private JLabel mPortLabel;
    private JLabel mEnableLabel;
    private JLabel mBacklogLabel;

    // Label for SSL EE port
    private JLabel mSSLPortLabel;
    private JLabel mSSLBacklogLabel;

    private JCheckBox mEnable;

    private CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private boolean mBlankFieldError = false;
    private boolean mNumberError = false;
    private CMSTabPanel mParent;
    private static final String HELPINDEX = "configuration-system-network-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSNetworkPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mParent = parent;
        mModel = parent.getResourceModel();
        mHelpToken = HELPINDEX;
    }
    
    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual Instanciation of the UI components
     */
    public void init() {
        Debug.println("NetworkPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
		GridBagLayout gb = new GridBagLayout();
	    GridBagConstraints gbc = new GridBagConstraints();
		CMSAdminUtil.resetGBC(gbc);
		mCenterPanel.setLayout(gb);

		// admin panel
        JPanel adminPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        adminPanel.setLayout(gb1);
        adminPanel.setBorder(makeTitledBorder("ADMIN"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(adminPanel, gbc);
        mCenterPanel.add(adminPanel);

        CMSAdminUtil.resetGBC(gbc);
        JLabel adminSSLport = makeJLabel("ADMINSSLPORT");
        mAdminSSLPortText = makeJTextField(10);
        JLabel adminBacklog = makeJLabel("ADMINBACKLOG");
        mAdminSSLBacklogText = makeJTextField(10);
        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.addEntryField(adminPanel, adminSSLport, 
          mAdminSSLPortText, adminBacklog, mAdminSSLBacklogText, dummy1, gbc);

        mActiveColor = mAdminSSLPortText.getBackground();

        // gateway panel
        JPanel agentPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        agentPanel.setLayout(gb2);
        agentPanel.setBorder(makeTitledBorder("AGENT"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(agentPanel, gbc);
        mCenterPanel.add(agentPanel);
        
        CMSAdminUtil.resetGBC(gbc);
        JLabel agentPort = makeJLabel("AGENTSSLPORT");
        mAgentSSLPortText = makeJTextField(10);
        JLabel agentBacklog = makeJLabel("SECUREAGENTBACKLOG");
        mAgentSSLBacklogText = makeJTextField(10);
        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.addEntryField(agentPanel, agentPort, mAgentSSLPortText,
          agentBacklog, mAgentSSLBacklogText, dummy, gbc);

        JPanel gatewayPanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        gatewayPanel.setLayout(gb3);
        gatewayPanel.setBorder(makeTitledBorder("EE"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(gatewayPanel, gbc);
        mCenterPanel.add(gatewayPanel);

        CMSAdminUtil.resetGBC(gbc);
        mPortLabel = makeJLabel("GATEWAYPORT");
        mGatewayPortText = makeJTextField(10);
        mBacklogLabel = makeJLabel("EEBACKLOG");
        mGatewayBacklogText = makeJTextField(10);
        mEnableLabel = makeJLabel("ENABLED");
        mEnable = makeJCheckBox();
        CMSAdminUtil.addEntryField(gatewayPanel, mPortLabel, mGatewayPortText, 
          mBacklogLabel, mGatewayBacklogText, mEnableLabel, mEnable, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSSLPortLabel = makeJLabel("GATEWAYSSLPORT");
        mGatewaySSLPortText = makeJTextField(10);
        mSSLBacklogLabel = makeJLabel("SECUREEEBACKLOG");
        mGatewaySSLBacklogText = makeJTextField(10);
        JLabel dummy2 = new JLabel(" ");
        CMSAdminUtil.addEntryField(gatewayPanel, mSSLPortLabel, 
          mGatewaySSLPortText, mSSLBacklogLabel, mGatewaySSLBacklogText,
          dummy2, gbc);
          
        refresh();
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        String adminSSLPortStr = mAdminSSLPortText.getText().trim();
        String gatewayPortStr = mGatewayPortText.getText().trim();
        String gatewaySSLPortStr = mGatewaySSLPortText.getText().trim();
        String agentSSLPortStr = mAgentSSLPortText.getText().trim();
        String adminSSLBacklogStr = mAdminSSLBacklogText.getText().trim();
        String gatewayBacklogStr = mGatewayBacklogText.getText().trim();
        String gatewaySSLBacklogStr = mGatewaySSLBacklogText.getText().trim();
        String agentSSLBacklogStr = mAgentSSLBacklogText.getText().trim();
        //String docroot = mDocRootText.getText().trim();

        //check blank fields
        if (adminSSLPortStr.equals("") || 
          (gatewayPortStr.equals("") && mGatewayPortText.isEnabled()) ||
          (gatewaySSLPortStr.equals("") && mGatewaySSLPortText.isEnabled()) || 
          agentSSLPortStr.equals("") || 
          adminSSLBacklogStr.equals("") || 
          (gatewayBacklogStr.equals("") && mGatewayBacklogText.isEnabled()) ||
          (gatewaySSLBacklogStr.equals("") && mGatewaySSLBacklogText.isEnabled()) ||
          agentSSLBacklogStr.equals("") ) { 
            showMessageDialog("BLANKFIELD");
            return false;
        }

        //check format and range number
        int adminSSLPort;
        int gatewayPort;
        int gatewaySSLPort;
        int agentSSLPort;
        int adminSSLBacklog;
        int gatewayBacklog;
        int gatewaySSLBacklog;
        int agentSSLBacklog;

        try {
            adminSSLPort = Integer.parseInt(adminSSLPortStr);
            gatewayPort = Integer.parseInt(gatewayPortStr);
            gatewaySSLPort = Integer.parseInt(gatewaySSLPortStr);
            agentSSLPort = Integer.parseInt(agentSSLPortStr);
            adminSSLBacklog = Integer.parseInt(adminSSLBacklogStr);
            gatewayBacklog = Integer.parseInt(gatewayBacklogStr);
            gatewaySSLBacklog = Integer.parseInt(gatewaySSLBacklogStr);
            agentSSLBacklog = Integer.parseInt(agentSSLBacklogStr);
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        if (adminSSLBacklog <= 0 || gatewayBacklog <= 0 ||
          gatewaySSLBacklog <= 0 || agentSSLBacklog <= 0) {
            showMessageDialog("NEGATIVE");
            return false;
        }
        if ((adminSSLPort < MIN_PORT) || (adminSSLPort > MAX_PORT) ||
          (gatewayPort < MIN_PORT) || (gatewayPort > MAX_PORT) ||
          (agentSSLPort < MIN_PORT) || (agentSSLPort > MAX_PORT) ||
          (gatewaySSLPort < MIN_PORT) || (gatewaySSLPort > MAX_PORT)) {
            showMessageDialog("PORTRANGE");
            return false;
        } else {
            mModel.progressStart();
            NameValuePairs nvps = new NameValuePairs();
            nvps.put(Constants.PR_ADMIN_S_PORT, adminSSLPortStr);
            nvps.put(Constants.PR_GATEWAY_PORT, gatewayPortStr);
            nvps.put(Constants.PR_AGENT_S_PORT, agentSSLPortStr);

            if (mGatewaySSLPortText.isEnabled()) {
                nvps.put(Constants.PR_GATEWAY_S_PORT, gatewaySSLPortStr);
            }

            if (mGatewaySSLBacklogText.isEnabled()) {
                nvps.put(Constants.PR_GATEWAY_S_BACKLOG, gatewaySSLBacklogStr);
            }

            if (mEnable.isSelected()) {
                nvps.put(Constants.PR_GATEWAY_PORT_ENABLED, Constants.TRUE);
                nvps.put(Constants.PR_ADMIN_S_BACKLOG, adminSSLBacklogStr);
                nvps.put(Constants.PR_GATEWAY_BACKLOG, gatewayBacklogStr);
                nvps.put(Constants.PR_AGENT_S_BACKLOG, agentSSLBacklogStr);
            } else
                nvps.put(Constants.PR_GATEWAY_PORT_ENABLED, Constants.FALSE);

            try {
                mAdmin.modify(DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_NETWORK,
                  Constants.RS_ID_CONFIG, nvps);
            } catch (EAdminException e) {
                showErrorDialog(e.toString());
                mModel.progressStop();
                return false;
            }

            ConsoleInfo consoleInfo = mModel.getConsoleInfo();
            LDAPConnection conn = consoleInfo.getLDAPConnection();
            try {
                LDAPAttribute attr = new LDAPAttribute("nsserverport", adminSSLPortStr);
                LDAPModification singleChange = new LDAPModification(LDAPModification.REPLACE,
                  attr);
                conn.modify(consoleInfo.getCurrentDN(), singleChange);
            } catch (Exception eee) {
            }
            mModel.progressStop();
        }

        clearDirtyFlag();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        refresh();
        //clearDirtyFlag();
        return true;
    }

    /**
	 * refresh the panel and update data
	 */
    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_ADMIN_S_PORT, "");
        nvps.put(Constants.PR_AGENT_S_PORT, "");
        nvps.put(Constants.PR_GATEWAY_S_PORT, "");
        nvps.put(Constants.PR_GATEWAY_PORT, "");
        nvps.put(Constants.PR_GATEWAY_PORT_ENABLED, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_NETWORK, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (e.getSource().equals(mEnable)) {
            if (mEnable.isSelected()) {
                enableFields(true, mActiveColor);
            } else {
                enableFields(false, getBackground());
            }
        }
    }

    private void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String str = nvps.get(name);

            if (name.equals(Constants.PR_GATEWAY_PORT_ENABLED)) {
                mEnable.setSelected(getBoolean(str));
            } else {
                if (!validate(str))
                    continue;

                if (name.equals(Constants.PR_AGENT_S_PORT)) {
                    mAgentSSLPortText.setText(str);
                } else if (name.equals(Constants.PR_ADMIN_S_PORT)) {
                    mAdminSSLPortText.setText(str);
                } else if (name.equals(Constants.PR_GATEWAY_S_PORT)) {
                    if (str.equals(DISABLED)) {
                        mGatewaySSLPortText.setText("");
                        enableFields(mSSLPortLabel, mGatewaySSLPortText, false,
                          getBackground());
                    } else {
                        mGatewaySSLPortText.setText(str);
                        enableFields(mSSLPortLabel, mGatewaySSLPortText, true,
                          mActiveColor);
                    }
                } else if (name.equals(Constants.PR_GATEWAY_PORT)) {
                    if (str.equals(DISABLED)) {
                        mGatewayPortText.setText("");
                        enableFields(mEnable, false);
                    } else {
                        mGatewayPortText.setText(str);
                        enableFields(mEnable, true);
                    }
                } else if (name.equals(Constants.PR_ADMIN_S_BACKLOG)) {
                    mAdminSSLBacklogText.setText(str);
                } else if (name.equals(Constants.PR_AGENT_S_BACKLOG)) {
                    mAgentSSLBacklogText.setText(str);
                } else if (name.equals(Constants.PR_GATEWAY_S_BACKLOG)) {
                    if (str.equals(DISABLED)) {
                        enableFields(mSSLBacklogLabel, mGatewaySSLBacklogText, 
                          false, getBackground());
                        mGatewaySSLBacklogText.setText("");
                    } else {
                        enableFields(mSSLBacklogLabel, mGatewaySSLBacklogText, 
                          true, mActiveColor);
                        mGatewaySSLBacklogText.setText(str);
                    }
                } else if (name.equals(Constants.PR_GATEWAY_BACKLOG)) {
                    if (str.equals(DISABLED)) {
                        enableFields(mEnable, false);
                        mGatewayBacklogText.setText("");
                    } else {
                        enableFields(mEnable, true);
                        mGatewayBacklogText.setText(str);
                    }
                }
            }
        }

        if (mEnable.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());
    }

    private boolean getBoolean(String val) {
        if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    private void enableFields(boolean enabled, Color color) {
        mGatewayPortText.setEnabled(enabled);
        mGatewayPortText.setEditable(enabled);
        mGatewayPortText.setBackground(color);
        mGatewayBacklogText.setEnabled(enabled);
        mGatewayBacklogText.setEditable(enabled);
        mGatewayBacklogText.setBackground(color);
        mPortLabel.setEnabled(enabled);
        mBacklogLabel.setEnabled(enabled);

        invalidate();
        validate();
        repaint(1);
    }

    private void enableFields(JLabel label, JTextComponent text, 
      boolean enabled, Color color) {
        label.setEnabled(enabled);
        text.setEnabled(enabled);
        text.setEditable(enabled);
        text.setBackground(color);
        CMSAdminUtil.repaintComp(label);
        CMSAdminUtil.repaintComp(text);
    }

    private void enableFields(JCheckBox comp, boolean enabled) {
        comp.setEnabled(enabled);
        CMSAdminUtil.repaintComp(comp);
    }

    private boolean validate(String str) {
        if (str.equals("")) {
            if (!mBlankFieldError) {
                showMessageDialog("BLANKFIELD");
                mBlankFieldError = true;
            }
            return false;
        }

        try {
            int sslPort = Integer.parseInt(str);
        } catch (NumberFormatException e) {
            if (!mNumberError) {
                showMessageDialog("NUMBERFORMAT");
                mNumberError = true;
            }
            return false;
        }
        return true;
    }
}

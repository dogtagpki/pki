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
package com.netscape.admin.certsrv.config.install;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Network panel for configurating the admin and EE port.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
class WINetworkPage extends WizardBasePanel implements IWizardPanel {
    private Color mActiveColor;

    // TextField for port
    private JTextField mAdminSSLPortText;
    private JTextField mAgentSSLPortText;
    private JTextField mGatewayPortText;
    private JTextField mGatewaySSLPortText;
    private JCheckBox mEnable;

    private JTextArea mAgentDesc;
    private JLabel mAgentPortLbl;
    private JTextField mPortText;

    protected AdminConnection mAdmin;
    private boolean mBlankFieldError = false;
    private boolean mNumberError = false;
    private JLabel mPortLabel, mSSLPortLabel;

    private static final String HELPINDEX =
      "install-network-configuration-wizard-help";
    private static final String PANELNAME = "NETWORKWIZARD";
    private static final int MAX_PORT = 65535;
    private static final int MIN_PORT = 1;
    private boolean mEnableEEPorts;
    private InstallWizardInfo mWizardInfo;
    private boolean mWarning;

    WINetworkPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WINetworkPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        mWizardInfo = wizardInfo;
        if (wizardInfo.isNetworkDone())
            return false;
        setBorder(makeTitledBorder(PANELNAME));
        boolean cloning =  mWizardInfo.isCloning();
        String selected_sub = mWizardInfo.getCloneSubsystem();
        if (!cloning ||
          (cloning && (selected_sub != null && !selected_sub.equals("ca")))) {
            mAgentDesc.setVisible(false);
            mAgentPortLbl.setVisible(false);
            mPortText.setVisible(false);
        }

        if (wizardInfo.isOCSPInstalled() || wizardInfo.isOCSPServiceAdded()) {
          mEnable.setSelected(true);
        } else {
          mEnable.setSelected(wizardInfo.isEEEnabled());
        }

        if (wizardInfo.isRAInstalled())
            mEnable.setSelected(true);
        mAdminSSLPortText.setText(wizardInfo.getAdminPort());
        mAgentSSLPortText.setText(wizardInfo.getAgentPort());
        if (!wizardInfo.isCAInstalled() && !wizardInfo.isRAInstalled() &&
          wizardInfo.isKRAInstalled()) {
            enableFields(mPortLabel, mGatewayPortText, false, getBackground());
            enableFields(mSSLPortLabel, mGatewaySSLPortText, false, getBackground());
              mEnable.setEnabled(false);
              mEnableEEPorts = false;
        } else {
            mGatewaySSLPortText.setText(wizardInfo.getEESecurePort());
            mGatewayPortText.setText(wizardInfo.getEEPort());
            mEnable.setEnabled(true);
            if (mEnable.isSelected()) {
                enableFields(true, mActiveColor);
                enableFields(mPortLabel, mGatewayPortText, true, mActiveColor);
            } else {
                enableFields(false, getBackground());
                enableFields(mPortLabel, mGatewayPortText, false, getBackground());
            }
            enableFields(mSSLPortLabel, mGatewaySSLPortText, true, mActiveColor);
            mEnableEEPorts = true;
        }

        return true;
    }

    private void enableFields(JComponent comp1, JTextComponent comp2,
      boolean enable, Color color) {
        if (comp1 != null) {
            comp1.setEnabled(enable);
            CMSAdminUtil.repaintComp(comp1);
        }
        if (comp2 != null) {
            comp2.setEnabled(enable);
            comp2.setBackground(color);
            comp2.setEditable(enable);
            CMSAdminUtil.repaintComp(comp2);
        }
    }

    public boolean validatePanel() {
        String adminPort = mAdminSSLPortText.getText().trim();
        String agentPort = mAgentSSLPortText.getText().trim();
        String eePort = mGatewayPortText.getText().trim();
        String sslEEPort = mGatewaySSLPortText.getText().trim();
        String masteragentport = mPortText.getText().trim();

        if (adminPort.equals("") || agentPort.equals("")) {
            setErrorMessage("BLANKFIELD");
            return false;
        }

        if (mEnableEEPorts) {
            if (sslEEPort.equals("") || (mEnable.isSelected() && eePort.equals(""))) {
                setErrorMessage("BLANKFIELD");
                return false;
            }
        }

        boolean cloning =  mWizardInfo.isCloning();
        String selected_sub = mWizardInfo.getCloneSubsystem();
        if (cloning && (selected_sub != null && selected_sub.equals("ca"))) {
            if (masteragentport.equals("")) {
                setErrorMessage("BLANKFIELD");
                return false;
            }
        }

        int num = 0;
        try {
            num = Integer.parseInt(adminPort);
            if (num < MIN_PORT || num > MAX_PORT) {
                setErrorMessage("PORTRANGE");
                return false;
            }
            num = Integer.parseInt(agentPort);
            if (num < MIN_PORT || num > MAX_PORT) {
                setErrorMessage("PORTRANGE");
                return false;
            }
            if (mEnableEEPorts) {
                num = Integer.parseInt(sslEEPort);
                if (num < MIN_PORT || num > MAX_PORT) {
                    setErrorMessage("PORTRANGE");
                    return false;
                }
                if (mEnable.isSelected()) {
                    num = Integer.parseInt(eePort);
                    if (num < MIN_PORT || num > MAX_PORT) {
                        setErrorMessage("PORTRANGE");
                        return false;
                    }
                }
            }
            if (cloning && (selected_sub != null && selected_sub.equals("ca")))
                num = Integer.parseInt(masteragentport);
        } catch (NumberFormatException e) {
            setErrorMessage("NUMBERFORMAT");
            return false;
        }

        if (adminPort.equals(agentPort) || agentPort.equals(sslEEPort) ||
          (mEnable.isSelected() && eePort.equals(sslEEPort))) {
            setErrorMessage("SAMEPORT");
            return false;
        }

        if (mEnableEEPorts) {
            if (agentPort.equals(sslEEPort) ||
              (mEnable.isSelected() && eePort.equals(sslEEPort))) {
                setErrorMessage("SAMEPORT");
                return false;
            }
        }
        setErrorMessage("");
        return true;
    }

    private void setEEPorts(InstallWizardInfo wizardInfo, Hashtable data) {
        String eePort = mGatewayPortText.getText().trim();
        String eeSSLPort = mGatewaySSLPortText.getText().trim();
        wizardInfo.setEEPort(eePort);
        wizardInfo.setEESecurePort(eeSSLPort);
        data.put(ConfigConstants.PR_EE_PORT, eePort);
        data.put(ConfigConstants.PR_EE_SECURE_PORT, eeSSLPort);
        if (mEnable.isSelected()) {
            data.put(ConfigConstants.PR_EE_PORT_ENABLE,
              ConfigConstants.TRUE);
            wizardInfo.setEEEnable(ConfigConstants.TRUE);
        } else {
            data.put(ConfigConstants.PR_EE_PORT_ENABLE,
              ConfigConstants.FALSE);
            wizardInfo.setEEEnable(ConfigConstants.FALSE);
        }
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
        CMSConfigCert configCertCgi = new CMSConfigCert();
        configCertCgi.initialize(wizardInfo);
        Hashtable data = new Hashtable();
        data.put(ConfigConstants.TASKID, TaskId.TASK_CONFIGURE_NETWORK);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
        String agentPort = mAgentSSLPortText.getText().trim();
        String radmPort = mAdminSSLPortText.getText().trim();
        wizardInfo.setAgentPort(agentPort);
        wizardInfo.setAdminPort(radmPort);
        data.put(ConfigConstants.PR_AGENT_PORT, agentPort);
        data.put(ConfigConstants.PR_RADM_PORT, radmPort);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
          consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
        boolean cloning =  mWizardInfo.isCloning();
        String selected_sub = mWizardInfo.getCloneSubsystem();
        if (cloning && (selected_sub != null && selected_sub.equals("ca")))
            data.put(Constants.PR_MASTER_AGENT_PORT, mPortText.getText().trim());

        if (mEnableEEPorts) {
            setEEPorts(wizardInfo, data);
            data.put(ConfigConstants.PR_EE_PORTS_ENABLE, ConfigConstants.TRUE);
        } else
            data.put(ConfigConstants.PR_EE_PORTS_ENABLE, ConfigConstants.FALSE);

        startProgressStatus();
        boolean ready = configCertCgi.configCert(data);
        endProgressStatus();

        if (!ready) {
            String str = configCertCgi.getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea heading = createTextArea(mResource.getString(
          "NETWORKWIZARD_TEXT_DESC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(heading, gbc);

        JLabel adminSSLport = makeJLabel("ADMINSSLPORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(adminSSLport, gbc);

        mAdminSSLPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mAdminSSLPortText, gbc);
        mActiveColor = mAdminSSLPortText.getBackground();

        JLabel dummy2a = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy2a, gbc);

        JLabel agentPort = makeJLabel("AGENTSSLPORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(agentPort, gbc);

        mAgentSSLPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        //gbc.gridwidth = gbc.REMAINDER;
        add(mAgentSSLPortText, gbc);

        JLabel dummy2b = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy2b, gbc);

        mSSLPortLabel = makeJLabel("GATEWAYSSLPORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.EAST;
        add(mSSLPortLabel, gbc);

        mGatewaySSLPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        //gbc.fill = gbc.NONE;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.anchor = gbc.WEST;
        //gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mGatewaySSLPortText, gbc);

        JLabel dummy2c = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy2c, gbc);

        mPortLabel = makeJLabel("GATEWAYPORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,COMPONENT_SPACE);
        add(mPortLabel, gbc);

        mGatewayPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        //gbc.fill = gbc.NONE;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.anchor = gbc.WEST;
        add(mGatewayPortText, gbc);

   // 610632 - remove the enable button

        JLabel enableLbl = makeJLabel("ENABLED");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.CENTER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
   //     add(enableLbl, gbc);

        mEnable = new JCheckBox();
        mEnable.addActionListener(this);
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
        COMPONENT_SPACE);
  //      add(mEnable, gbc);

        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mAgentDesc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING1_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(2*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mAgentDesc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mAgentPortLbl = makeJLabel("AGENTPORT");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mAgentPortLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPortText, gbc);

        JLabel dummy2 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy2, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (mEnable.isSelected()) {
            enableFields(true, mActiveColor);
        } else {
            if (!mWarning && (mWizardInfo.isOCSPInstalled() || mWizardInfo.isOCSPServiceAdded())) {
                mWarning = true;
                String errormsg = mResource.getString(mPanelName+"_WARNING");
                JOptionPane.showMessageDialog(mAdminFrame, errormsg, "Warning",
                  JOptionPane.WARNING_MESSAGE,
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON));
            } else {
                enableFields(false, getBackground());
            }
        }
    }

    private void enableFields(boolean enable, Color color) {
        mPortLabel.setEnabled(enable);
        mGatewayPortText.setEnabled(enable);
        mGatewayPortText.setEditable(enable);
        mGatewayPortText.setBackground(color);
        CMSAdminUtil.repaintComp(mPortLabel);
        CMSAdminUtil.repaintComp(mGatewayPortText);
    }
}

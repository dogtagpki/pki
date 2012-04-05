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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.awt.event.*;

/**
 * Remote subsystems.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */

class WIRemoteKRASubsystem extends WizardBasePanel implements IWizardPanel {
    protected JTextField mHostText, mPortText, mTimeoutText;
    protected JLabel mHostLbl, mPortLbl, mTimeoutLbl, mTimeunitLbl;
    protected JRadioButton mYes, mNo;
    protected String mHost, mPort, mTimeout;
    protected JTextArea mHeading;
    protected Color mActiveColor;
    public static final int MAX_PORT = 65535;
    public static final int MIN_PORT = 1;
    private static final String PANELNAME = "REMOTEKRAWIZARD";
    private static final String HELPINDEX1 = "install-ca-remote-kra-wizard-help";
    private static final String HELPINDEX2 = "install-ra-remote-kra-wizard-help";
    private InstallWizardInfo mWizardInfo;

    WIRemoteKRASubsystem(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIRemoteKRASubsystem(JDialog parent, JFrame adminFrame) {
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
        if (wizardInfo.isServicesDone())
            return false;
        if ((wizardInfo.isCAInstalled() || wizardInfo.isRAInstalled())
          && !wizardInfo.isKRAInstalled()) {
            setBorder(makeTitledBorder(PANELNAME));
            if (mYes.isSelected())
                enableFields(true, mActiveColor);
            else
                enableFields(false, getBackground());
            return true;
        }
        return false;
    }

    public boolean validatePanel() {
        if (mNo.isSelected()) {
            mHost = "";
            mPort = "";
            mTimeout = "";
            return true;
        }

        mHost = mHostText.getText().trim();
        mPort = mPortText.getText().trim();
        mTimeout = mTimeoutText.getText().trim();
        if (mHost.equals("")) {
            setErrorMessage("BLANKHOST");
            return false;
        }
        if (mPort.equals("")) {
            setErrorMessage("BLANKPORT");
            return false;
        }
        if (mTimeout.equals("")) {
            setErrorMessage("BLANKTIMEOUT");
            return false;
        }

        try {
            int portnumber = Integer.parseInt(mPort);
            if (portnumber < MIN_PORT || portnumber > MAX_PORT) {
                setErrorMessage("OUTOFRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            setErrorMessage("INVALIDPORT");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.setDRMHost(mHost);
        wizardInfo.setDRMPort(mPort);
        wizardInfo.setDRMTimeout(mTimeout);
        ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
        CMSConfigCert configCertCgi = new CMSConfigCert();
        configCertCgi.initialize(wizardInfo);
        Hashtable data = new Hashtable();
        data.put(ConfigConstants.TASKID,TaskId.TASK_SELECT_SUBSYSTEMS);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
          consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
        if (wizardInfo.getDBBindDN() != null)
            data.put(ConfigConstants.PR_DB_BINDDN, wizardInfo.getDBBindDN());
        if (wizardInfo.getInternalDBPasswd() != null)
            data.put(ConfigConstants.PR_DB_PWD, wizardInfo.getInternalDBPasswd());

        if (wizardInfo.isCAInstalled())
            data.put(ConfigConstants.PR_CA, ConfigConstants.TRUE);
        else
            data.put(ConfigConstants.PR_CA, ConfigConstants.FALSE);

        if (wizardInfo.isRAInstalled())
            data.put(ConfigConstants.PR_RA, ConfigConstants.TRUE);
        else
            data.put(ConfigConstants.PR_RA, ConfigConstants.FALSE);

        if (wizardInfo.isKRAInstalled())
            data.put(ConfigConstants.PR_KRA, ConfigConstants.TRUE);
        else
            data.put(ConfigConstants.PR_KRA, ConfigConstants.FALSE);

        String services = "";
        if (wizardInfo.isCAInstalled()) {
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_CA;
        } else {
            data.put(ConfigConstants.CA_HOST, wizardInfo.getCMHost());
            data.put(ConfigConstants.CA_PORT, wizardInfo.getCMPort());
            data.put(ConfigConstants.CA_TIMEOUT, wizardInfo.getCMTimeout());
        }

        if (wizardInfo.isRAInstalled()) {
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_RA;
        }
        if (wizardInfo.isKRAInstalled()) {
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_KRA;
        } else {
            // connect to the remote KRA subystem
            if (mYes.isSelected()) {
                data.put(ConfigConstants.KRA_HOST, wizardInfo.getDRMHost());
                data.put(ConfigConstants.KRA_PORT, wizardInfo.getDRMPort());
                data.put(ConfigConstants.KRA_TIMEOUT, wizardInfo.getDRMTimeout());
                data.put(ConfigConstants.REMOTE_KRA_ENABLED,
                  ConfigConstants.TRUE);
                wizardInfo.enableRemoteDRM(ConfigConstants.TRUE);
            } else {
                data.put(ConfigConstants.REMOTE_KRA_ENABLED,
                  ConfigConstants.FALSE);
                wizardInfo.enableRemoteDRM(ConfigConstants.FALSE);
            }
        }

        data.put(ConfigConstants.PR_SUBSYSTEMS, services);
        wizardInfo.setSubsystems(services);
        startProgressStatus();
        CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CONFIGDB");
        boolean ready = configCertCgi.configCert(data);
        dlg.setVisible(false);

        endProgressStatus();

        if (!ready) {
            String str = configCertCgi.getErrorMessage();
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

        return ready;
    }

    public void callHelp() {
        if (mWizardInfo.isCAInstalled()) {
            CMSAdminUtil.help(HELPINDEX1);
        } else {
            CMSAdminUtil.help(HELPINDEX2);
        }
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea heading = createTextArea(mResource.getString(
            "REMOTEKRAWIZARD_TEXT_ISREMOTEKRA_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading, gbc);

        mNo = makeJRadioButton("NO", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNo, gbc);

        mYes = makeJRadioButton("YES", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mYes, gbc);

        ButtonGroup btnGroup = new ButtonGroup();
        btnGroup.add(mNo);
        btnGroup.add(mYes);

        mHeading = createTextArea(mResource.getString(
            "REMOTEKRAWIZARD_TEXT_HEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mHeading, gbc);

        mHostLbl = makeJLabel("HOST");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(mHostLbl, gbc);

        mHostText = makeJTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostText, gbc);
        mActiveColor = mHostText.getBackground();

        mPortLbl = makeJLabel("PORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mPortLbl, gbc);

        mPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPortText, gbc);

        mTimeoutLbl = makeJLabel("TIMEOUT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(mTimeoutLbl, gbc);

        mTimeoutText = makeJTextField("30", 10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTimeoutText, gbc);

        /*mTimeunitLbl = makeJLabel("TIMEUNIT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(mTimeunitLbl, gbc);
        */

        JLabel label = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(label, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (mYes.isSelected()) {
            enableFields(true, mActiveColor);
        } else {
            enableFields(false, getBackground());
        }
    }

    private void enableFields(boolean enabled, Color color) {
        mHeading.setEnabled(enabled);
        mHostLbl.setEnabled(enabled);
        mPortLbl.setEnabled(enabled);
        mTimeoutLbl.setEnabled(enabled);
        mHostText.setEnabled(enabled);
        mHostText.setEditable(enabled);
        mHostText.setBackground(color);
        mPortText.setEnabled(enabled);
        mPortText.setEditable(enabled);
        mPortText.setBackground(color);
        mTimeoutText.setEnabled(enabled);
        mTimeoutText.setEditable(enabled);
        mTimeoutText.setBackground(color);
        CMSAdminUtil.repaintComp(mHeading);
        CMSAdminUtil.repaintComp(mHostLbl);
        CMSAdminUtil.repaintComp(mHostText);
        CMSAdminUtil.repaintComp(mPortLbl);
        CMSAdminUtil.repaintComp(mPortText);
        CMSAdminUtil.repaintComp(mTimeoutLbl);
        CMSAdminUtil.repaintComp(mTimeoutText);
    }
}


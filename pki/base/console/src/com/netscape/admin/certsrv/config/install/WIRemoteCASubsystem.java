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
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.certsrv.common.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;

/**
 * Remote subsystems.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */

class WIRemoteCASubsystem extends WizardBasePanel implements IWizardPanel {
    protected JTextField mHostText;
    protected JTextField mPortText;
    protected JTextField mTimeoutText;
    protected String mHost;
    protected String mPort;
    protected String mTimeout;
    private String mHelpIndex;
    public static final int MAX_PORT = 65535;
    public static final int MIN_PORT = 1;
    private static final String PANELNAME = "REMOTECAWIZARD";
    private static final String RAHELPINDEX = "install-remote-ca-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakra-remote-ca-wizard-help";

    WIRemoteCASubsystem(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIRemoteCASubsystem(JDialog parent, JFrame adminFrame) {
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
        if (wizardInfo.isServicesDone())
            return false;
        if (wizardInfo.isRAInstalled() && !wizardInfo.isCAInstalled()) {
            setBorder(makeTitledBorder(PANELNAME));
            if (wizardInfo.isKRAInstalled()) 
                mHelpIndex = RAKRAHELPINDEX;
            else
                mHelpIndex = RAHELPINDEX;

            return true;
        }

        return false;
    }

    public boolean validatePanel() {
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
        wizardInfo.setCMHost(mHost);
        wizardInfo.setCMPort(mPort);   
        wizardInfo.setCMTimeout(mTimeout);   

        if ((wizardInfo.isCAInstalled() || wizardInfo.isRAInstalled())
          && !wizardInfo.isKRAInstalled()) {
            return true;
        }

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
        }
        if (wizardInfo.isRAInstalled()) {
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_RA;
            //data.put(ConfigConstants.CA_HOST, wizardInfo.getCMHost());
            //data.put(ConfigConstants.CA_PORT, wizardInfo.getCMPort());
        }
        if (wizardInfo.isKRAInstalled()) {
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_KRA;
        }
        data.put(ConfigConstants.PR_SUBSYSTEMS, services);
        data.put(ConfigConstants.REMOTE_KRA_ENABLED, ConfigConstants.FALSE);
        data.put(ConfigConstants.CA_HOST, wizardInfo.getCMHost());
        data.put(ConfigConstants.CA_PORT, wizardInfo.getCMPort());
        data.put(ConfigConstants.CA_TIMEOUT, wizardInfo.getCMTimeout());
        wizardInfo.enableRemoteDRM(ConfigConstants.FALSE);
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
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea heading = createTextArea(mResource.getString(
            "REMOTECAWIZARD_TEXT_HEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading, gbc);

        JLabel hostLbl = makeJLabel("HOST");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(hostLbl, gbc);

        mHostText = makeJTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostText, gbc);

        JLabel portLbl = makeJLabel("PORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(portLbl, gbc);

        mPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPortText, gbc);

        JLabel timeoutLbl = makeJLabel("TIMEOUT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(timeoutLbl, gbc);

        mTimeoutText = makeJTextField("30", 10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTimeoutText, gbc);

        /*JLabel timeunitLbl = makeJLabel("TIMEUNIT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        add(timeunitLbl, gbc);
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
}


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
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICloneRAKeyCertPage extends WizardBasePanel implements IWizardPanel {
    private String mRANicknameStr, mSSLNicknameStr;
    private String mRATokenname, mSSLTokenname;
    protected InstallWizardInfo mWizardInfo;
    protected JComboBox mRANicknameBox, mSSLNicknameBox;
    private static final String PANELNAME = "CLONERAKEYCERTWIZARD";
    private static final String CAHELPINDEX =
      "install-racertclone-wizard-help";


    WICloneRAKeyCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        mRANicknameStr = "raSigningCert";
        mSSLNicknameStr = "Server-Cert";
        init();
    }

    WICloneRAKeyCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        mRANicknameStr = "raSigningCert";
        mSSLNicknameStr = "Server-Cert";
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        mWizardInfo = wizardInfo;
        if (!wizardInfo.isCloning())
            return false;
        if (!wizardInfo.isCloneRASubsystem())
            return false;
        if (wizardInfo.isRACloningDone())
            return false;
        if (!wizardInfo.isRAInstalled() ||
          wizardInfo.isRACertRequestDone())
            return false;

        setBorder(makeTitledBorder(PANELNAME));
        if (mRANicknameBox.getItemCount() > 0) {
            mRANicknameBox.removeAllItems();
        }

        if (mSSLNicknameBox.getItemCount() > 0) {
            mSSLNicknameBox.removeAllItems();
        }
        String certsList = mWizardInfo.getCloneCertsList();
        StringTokenizer t1 = new StringTokenizer(certsList, ";");
        while (t1.hasMoreTokens()) {
            String s1 = (String)t1.nextToken();
            if (s1.indexOf(mRANicknameStr) >= 0)
                mRANicknameBox.addItem(s1);
        }

        StringTokenizer t2 = new StringTokenizer(certsList, ";");
        while (t2.hasMoreTokens()) {
            String s1 = (String)t2.nextToken();
            if (s1.indexOf(mSSLNicknameStr) >= 0)
                mSSLNicknameBox.addItem(s1);
        }

        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        String ranickname = (String)mRANicknameBox.getSelectedItem();
        mRATokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        int index = ranickname.indexOf(":");
        if (index > -1) {
            mRATokenname = ranickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_RA_TOKEN_NAME, mRATokenname);

        String sslnickname = (String)mSSLNicknameBox.getSelectedItem();
        mSSLTokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        index = sslnickname.indexOf(":");
        if (index > -1) {
            mSSLTokenname = sslnickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_SSL_TOKEN_NAME, mSSLTokenname);

        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
        CMSConfigCert configCertCgi = new CMSConfigCert();
        configCertCgi.initialize(wizardInfo);
        Hashtable data = new Hashtable();
        data.put(ConfigConstants.TASKID,TaskId.TASK_CLONING);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
        data.put(ConfigConstants.PR_SUBSYSTEM, ConfigConstants.PR_RA);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
          consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
        data.put(ConfigConstants.PR_CLONE_RA_TOKEN_NAME, mRATokenname);
        data.put(ConfigConstants.PR_CLONE_RA_NICKNAME,
          mRANicknameBox.getSelectedItem());
        data.put(ConfigConstants.PR_CLONE_SSL_TOKEN_NAME, mSSLTokenname);
        data.put(ConfigConstants.PR_CLONE_SSL_NICKNAME,
          mSSLNicknameBox.getSelectedItem());

        startProgressStatus();
        boolean ready = configCertCgi.configCert(data);
        endProgressStatus();

        if (!ready) {
            String errstr = configCertCgi.getErrorMessage();
            if (errstr.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(errstr);
        }
        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(CAHELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea heading = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel raNicknameLbl = makeJLabel("RANICKNAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(raNicknameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRANicknameBox = new JComboBox();
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(mRANicknameBox, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea heading1 = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING1_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel sslNicknameLbl = makeJLabel("SSLNICKNAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(sslNicknameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSSLNicknameBox = new JComboBox();
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(mSSLNicknameBox, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
        mWizardInfo.setRATokenName(mRATokenname);
        mWizardInfo.setSSLTokenName(mSSLTokenname);
    }

    public void actionPerformed(ActionEvent e) {
    }
}

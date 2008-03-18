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
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WICloneTKSKeyCertPage extends WizardBasePanel implements IWizardPanel {
    private String mSSLNicknameStr, mSSLTokenname;
    protected InstallWizardInfo mWizardInfo;
    protected JComboBox mSSLNicknameBox;
    private static final String PANELNAME = "CLONETKSKEYCERTWIZARD";
    private static final String TKSHELPINDEX = 
      "install-tkscertclone-wizard-help";

    
    WICloneTKSKeyCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        mSSLNicknameStr = "Server-Cert";
        init();
    }

    WICloneTKSKeyCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
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
        if (!wizardInfo.isCloneTKSSubsystem())
            return false;
        if (wizardInfo.isTKSCloningDone())
            return false;

        setBorder(makeTitledBorder(PANELNAME));

        if (mSSLNicknameBox.getItemCount() > 0) {
            mSSLNicknameBox.removeAllItems();
        }
        String certsList = mWizardInfo.getCloneCertsList();
        StringTokenizer t = new StringTokenizer(certsList, ";");
        while (t.hasMoreTokens()) {
            String s1 = (String)t.nextToken();
            if (s1.indexOf(mSSLNicknameStr) >= 0)
                mSSLNicknameBox.addItem(s1);
        }

        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        String sslnickname = (String)mSSLNicknameBox.getSelectedItem();
        mSSLTokenname = Constants.PR_INTERNAL_TOKEN_NAME;
        int index = sslnickname.indexOf(":");
        if (index > -1) {
            mSSLTokenname = sslnickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_SSL_TOKEN_NAME, mSSLTokenname);

        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CLONING;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_SUBSYSTEM+"="+ConfigConstants.PR_TKS;
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_SSL_TOKEN_NAME+"="+
          mSSLTokenname;
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_SSL_NICKNAME+"="+
          mSSLNicknameBox.getSelectedItem();

        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String errstr = getErrorMessage();
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
        CMSAdminUtil.help(TKSHELPINDEX);
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
        mWizardInfo.setSSLTokenName(mSSLTokenname);
    }

    public void actionPerformed(ActionEvent e) {
    }
}

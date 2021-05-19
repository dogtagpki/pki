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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.StringTokenizer;

import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICloneKRAKeyCertPage extends WizardBasePanel implements IWizardPanel {
    private String mKRANicknameStr, mStorageNicknameStr, mSSLNicknameStr;
    private String mKRATokenname, mStorageTokenname, mSSLTokenname;
    protected InstallWizardInfo mWizardInfo;
    protected JComboBox<String> mKRANicknameBox, mStorageNicknameBox, mSSLNicknameBox;
    private static final String PANELNAME = "CLONEKRAKEYCERTWIZARD";
    private static final String KRAHELPINDEX =
      "install-kracertclone-wizard-help";


    WICloneKRAKeyCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        mKRANicknameStr = "kraTransportCert";
        mSSLNicknameStr = "Server-Cert";
        mStorageNicknameStr = "kraStorageCert";
        init();
    }

    WICloneKRAKeyCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        mKRANicknameStr = "kraTransportCert";
        mSSLNicknameStr = "Server-Cert";
        mStorageNicknameStr = "kraStorageCert";
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        mWizardInfo = wizardInfo;
        if (!wizardInfo.isCloning())
            return false;
        if (!wizardInfo.isCloneKRASubsystem())
            return false;
        if (wizardInfo.isKRACloningDone())
            return false;

        if (!wizardInfo.isKRAInstalled() ||
          wizardInfo.isKRACertRequestDone()) {
            return false;
        }

        setBorder(makeTitledBorder(PANELNAME));
        if (mKRANicknameBox.getItemCount() > 0) {
            mKRANicknameBox.removeAllItems();
        }

        if (mStorageNicknameBox.getItemCount() > 0) {
            mStorageNicknameBox.removeAllItems();
        }

        if (mSSLNicknameBox.getItemCount() > 0) {
            mSSLNicknameBox.removeAllItems();
        }
        String certsList = mWizardInfo.getCloneCertsList();
        StringTokenizer t1 = new StringTokenizer(certsList, ";");
        while (t1.hasMoreTokens()) {
            String s1 = t1.nextToken();
            if (s1.indexOf(mStorageNicknameStr) >= 0)
                mStorageNicknameBox.addItem(s1);
        }

        StringTokenizer t2 = new StringTokenizer(certsList, ";");
        while (t2.hasMoreTokens()) {
            String s1 = t2.nextToken();
            if (s1.indexOf(mSSLNicknameStr) >= 0)
                mSSLNicknameBox.addItem(s1);
        }

        StringTokenizer t3 = new StringTokenizer(certsList, ";");
        while (t3.hasMoreTokens()) {
            String s1 = t3.nextToken();
            if (s1.indexOf(mKRANicknameStr) >= 0)
                mKRANicknameBox.addItem(s1);
        }

        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        String kranickname = (String)mKRANicknameBox.getSelectedItem();
        mKRATokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        int index = kranickname.indexOf(":");
        if (index > -1) {
            mKRATokenname = kranickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_KRA_TOKEN_NAME, mKRATokenname);

        String storagenickname = (String)mStorageNicknameBox.getSelectedItem();
        mStorageTokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        index = storagenickname.indexOf(":");
        if (index > -1) {
            mStorageTokenname = storagenickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_STORAGE_TOKEN_NAME, mStorageTokenname);

        String sslnickname = (String)mSSLNicknameBox.getSelectedItem();
        mSSLTokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        index = sslnickname.indexOf(":");
        if (index > -1) {
            mSSLTokenname = sslnickname.substring(0, index);
        }
        mWizardInfo.put(ConfigConstants.PR_CLONE_SSL_TOKEN_NAME, mSSLTokenname);

        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CLONING;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_SUBSYSTEM+"="+ConfigConstants.PR_KRA;
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_KRA_TOKEN_NAME+"="+
          mKRATokenname;
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_KRA_NICKNAME+"="+
          mKRANicknameBox.getSelectedItem();
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_STORAGE_TOKEN_NAME+"="+
          mStorageTokenname;
        rawData = rawData+"&"+ConfigConstants.PR_CLONE_STORAGE_NICKNAME+"="+
          mStorageNicknameBox.getSelectedItem();
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

    @Override
    public void callHelp() {
        CMSAdminUtil.help(KRAHELPINDEX);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea heading = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(heading, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel kraNicknameLbl = makeJLabel("KRANICKNAME");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(kraNicknameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mKRANicknameBox = new JComboBox<>();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mKRANicknameBox, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea heading1 = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING1_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(heading1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel storageNicknameLbl = makeJLabel("STORAGENICKNAME");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(storageNicknameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mStorageNicknameBox = new JComboBox<>();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mStorageNicknameBox, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea heading2 = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING2_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(heading2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel sslNicknameLbl = makeJLabel("SSLNICKNAME");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(sslNicknameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSSLNicknameBox = new JComboBox<>();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSSLNicknameBox, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        add(dummy, gbc);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        mWizardInfo.setKRATokenName(mKRATokenname);
        mWizardInfo.setSSLTokenName(mSSLTokenname);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
    }
}

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

import java.awt.event.*;
import java.awt.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Replication Agreeemnt
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIReplAgreementPage extends WizardBasePanel implements IWizardPanel {
    private Color mActiveColor;
    private JCheckBox mEnable;
    private JTextField mAgreementText1, mAgreementText2;
    private JPasswordField mManagerPwd1, mManagerPwdAgain1;
    private JPasswordField mManagerPwd2, mManagerPwdAgain2;

    private static final String PANELNAME = "REPLDBWIZARD";
    private static final String HELPINDEX =
      "install-internaldb-configuration-wizard-help";
    private static final String EMPTYSTR = "                    ";

    WIReplAgreementPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIReplAgreementPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mEnable)) {
            enableAgreement(mEnable.isSelected());
        }
    }
	
    private void enableAgreement(boolean e) {
        Color c;
        if (e) {
            c = mActiveColor;
        } else {
            c = getBackground();
        }
        mAgreementText1.setEditable(e);
        mAgreementText1.setEnabled(e);
        mAgreementText1.setBackground(c);
        mManagerPwd1.setEditable(e);
        mManagerPwd1.setEnabled(e);
        mManagerPwd1.setBackground(c);
        mManagerPwdAgain1.setEditable(e);
        mManagerPwdAgain1.setEnabled(e);
        mManagerPwdAgain1.setBackground(c);
        mAgreementText2.setEditable(e);
        mAgreementText2.setEnabled(e);
        mAgreementText2.setBackground(c);
        mManagerPwd2.setEditable(e);
        mManagerPwd2.setEnabled(e);
        mManagerPwd2.setBackground(c);
        mManagerPwdAgain2.setEditable(e);
        mManagerPwdAgain2.setEnabled(e);
        mManagerPwdAgain2.setBackground(c);
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (!wizardInfo.isCloneDBCreated())
            return false;

        if (wizardInfo.isCloning() && !wizardInfo.isAgreementDone()) {
            setBorder(makeTitledBorder(PANELNAME));
            mAgreementText1.setText("masterToconsumer");
            mAgreementText2.setText("consumerTomaster");
            return true; 
        }
        return false;
    }

    public boolean validatePanel() {
        if (!mEnable.isSelected()) 
            return true;
        String passwd1 = mManagerPwd1.getText().trim();
        String passwdAgain1 = mManagerPwdAgain1.getText().trim();
        String name1 = mAgreementText1.getText().trim();

        if (passwd1.equals("") || passwdAgain1.equals("")) {
            setErrorMessage("EMPTYPASSWORD");
            return false;
        }
        
        if (!passwdAgain1.equals(passwd1)) {
            setErrorMessage("NOTSAMEPASSWORD");
            return false;
        }

        if (name1.equals("")) {
            setErrorMessage("EMPTYNAME");
            return false;
        }

        String passwd2 = mManagerPwd2.getText().trim();
        String passwdAgain2 = mManagerPwdAgain2.getText().trim();
        String name2 = mAgreementText2.getText().trim();
  
        if (passwd2.equals("") || passwdAgain2.equals("")) {
            setErrorMessage("EMPTYPASSWORD");
            return false;
        }
        
        if (!passwdAgain2.equals(passwd2)) {
            setErrorMessage("NOTSAMEPASSWORD");
            return false;
        }

        if (name2.equals("")) {
            setErrorMessage("EMPTYNAME");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CREATE_REPLICATION_AGREEMENT;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        boolean ready = false;
        if (!mEnable.isSelected()) {
            rawData = rawData+"&"+ConfigConstants.PR_ENABLE_REPLICATION+"="+
              ConfigConstants.FALSE;
            ready = send(rawData, wizardInfo);
        } else {
            rawData = rawData+"&"+ConfigConstants.PR_ENABLE_REPLICATION+"="+
              ConfigConstants.TRUE;
            rawData = rawData+"&"+ConfigConstants.PR_AGREEMENT_NAME_1+"="+
              mAgreementText1.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_REPLICATION_MANAGER_PASSWD_1+"="+mManagerPwd1.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_AGREEMENT_NAME_2+"="+mAgreementText2.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_REPLICATION_MANAGER_PASSWD_2+"="+mManagerPwd2.getText().trim();

            startProgressStatus();
/*
            CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, 
              "CGITASK", "CREATEREPLICATIONAGREEMENT");
*/
            ready = send(rawData, wizardInfo);
 //           dlg.setVisible(false);
            endProgressStatus();
        }

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
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

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEnable = makeJCheckBox("ENABLE");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEnable, gbc);
        mEnable.setSelected(true);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc1 = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_MASTER1_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdLbl1 = makeJLabel("PASSWORD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwdLbl1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mManagerPwd1 = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mManagerPwd1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdAgainLbl1 = makeJLabel("PASSWORDAGAIN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwdAgainLbl1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mManagerPwdAgain1 = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mManagerPwdAgain1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel desc2 = makeJLabel("MASTER2");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc2, gbc);
/*
        JTextArea desc2 = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_MASTER2_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc2, gbc);
*/

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdLbl2 = makeJLabel("PASSWORD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwdLbl2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mManagerPwd2 = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mManagerPwd2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdAgainLbl2 = makeJLabel("PASSWORDAGAIN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwdAgainLbl2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mManagerPwdAgain2 = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mManagerPwdAgain2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc3 = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_AGREEMENT_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(2*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc3, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc4 = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_AGREEMENT1_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc4, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel agreementLbl1 = makeJLabel("NAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(agreementLbl1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mAgreementText1 = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mAgreementText1, gbc);
        mActiveColor = mAgreementText1.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc5 = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_AGREEMENT2_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc5, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel agreementLbl2 = makeJLabel("NAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(agreementLbl2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mAgreementText2 = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mAgreementText2, gbc);
        mActiveColor = mAgreementText2.getBackground();

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.setAgreementDone(ConfigConstants.TRUE);
        if (!mEnable.isSelected())
            wizardInfo.setReplicationEnabled(ConfigConstants.FALSE);
        else
            wizardInfo.setReplicationEnabled(ConfigConstants.TRUE);
    }
}

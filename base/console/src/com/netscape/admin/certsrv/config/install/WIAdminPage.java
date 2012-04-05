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

import java.util.*;
import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.console.*;

/**
 * Admin page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIAdminPage extends WizardBasePanel implements IWizardPanel {
    private JCheckBox mEnable;
    private JTextField mIDText, mFullNameText, mPasswordText,
      mPasswordAgainText;
    private static final String PANELNAME = "ADMININSTALLWIZARD";
    private static final String HELPINDEX =
      "install-administrator-configuration-wizard-help";

    WIAdminPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIAdminPage(JDialog parent, JFrame adminFrame) {
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
        if (wizardInfo.isCloning() && wizardInfo.isAgreementDone() &&
          wizardInfo.isReplicationEnabled())
            return false;
        if (wizardInfo.isCloning() && !wizardInfo.isAgreementDone())
            return false;
        if (wizardInfo.isAdministratorDone())
           return false;
        mIDText.setText(wizardInfo.getCertAdminUid());
        mFullNameText.setText(wizardInfo.getCertAdminName());

        setBorder(makeTitledBorder(PANELNAME));

        return true;
    }

    public boolean validatePanel() {
        String password = mPasswordText.getText().trim();
        String passwordAgain = mPasswordAgainText.getText().trim();
        if (password.equals("") || passwordAgain.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }

        if (!password.equals(passwordAgain)) {
            setErrorMessage("NOTSAMEPASSWD");
            return false;
        }

        if (mIDText.getText().trim().equals("")) {
            setErrorMessage("BLANKADMINID");
            return false;
        }

        if (mFullNameText.getText().trim().equals("")) {
            setErrorMessage("BLANKADMINNAME");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_SETUP_ADMINISTRATOR;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_CERT_ADMINUID+"="+mIDText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_CERT_ADMINNAME+"="+mFullNameText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_CERT_ADMINPASSWD+"="+mPasswordAgainText.getText();
        if (mEnable.isSelected()) {
            rawData = rawData+"&"+ConfigConstants.PR_ENABLE+"=true";
        } else {
            rawData = rawData+"&"+ConfigConstants.PR_ENABLE+"=false";
        }
        if (wizardInfo.getInternalDBPasswd() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+wizardInfo.getInternalDBPasswd();
        wizardInfo.setCertAdminUid(mIDText.getText().trim());
        wizardInfo.setCertAdminName(mFullNameText.getText().trim());

        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

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
          "ADMININSTALLWIZARD_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel idLbl = makeJLabel("ADMINID");
        gbc.anchor = gbc.NORTHEAST;
        gbc.insets = new Insets(COMPONENT_SPACE,0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(idLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mIDText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mIDText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel nameLbl = makeJLabel("FULLNAME");
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.NORTHEAST;
        add(nameLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mFullNameText = makeJTextField(30);
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        add(mFullNameText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdLbl = makeJLabel("PASSWORD");
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        add(passwdLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPasswordText, gbc);

/*
        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy2 = createTextArea(" ", 1, 5);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(dummy2, gbc);
*/

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdAgainLbl = makeJLabel("PASSWORDAGAIN");
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        add(passwdAgainLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainText = makeJPasswordField(30);
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        add(mPasswordAgainText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwdAgainLbl1 = makeJLabel("DUMMY");
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.weighty = 1.0;
        add(passwdAgainLbl1, gbc);

        CMSAdminUtil.resetGBC(gbc);
       mEnable = makeJCheckBox("ENABLE");
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
       add(mEnable, gbc);
        mEnable.setSelected(true);
/*
        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy3 = createTextArea(" ", 1, 5);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy3, gbc);
*/
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

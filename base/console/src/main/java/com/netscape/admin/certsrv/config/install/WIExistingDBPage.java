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

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;

/**
 * This panel is for cloning. It lets the user to enter the configuration
 * information for the master database.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIExistingDBPage extends WizardBasePanel implements IWizardPanel {
    private JTextField mRMPortText, mRMBindAsText, mRMHostText;
    private JTextField mRMBaseDNText;
    private JPasswordField mRMPasswordText;

    private static final String PANELNAME = "EXISTINGDBWIZARD";
    private static final String HELPINDEX =
      "install-internaldb-configuration-wizard-help";

    WIExistingDBPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIExistingDBPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning() && !wizardInfo.isConnectDBDone()) {
            setBorder(makeTitledBorder(PANELNAME));
            mRMBindAsText.setText(wizardInfo.getDBBindDN());
            return true;
        }

        return false;
    }

    @Override
    public boolean validatePanel() {
        String rmhostname = mRMHostText.getText().trim();
        String rmport = mRMPortText.getText().trim();
        String rmbindDN = mRMBindAsText.getText().trim();
        String rmpasswd = mRMPasswordText.getText().trim();

        if (rmhostname.equals("")) {
            setErrorMessage("EMPTYHOST");
            return false;
        }

        if (rmport.equals("")) {
            setErrorMessage("EMPTYPORT");
            return false;
        }

        if (rmbindDN.equals("")) {
            setErrorMessage("EMPTYBINDDN");
            return false;
        }

        if (rmpasswd.equals("")) {
            setErrorMessage("EMPTYPASSWD");
            return false;
        }

        try {
            Integer num = Integer.valueOf(rmport);
        } catch (NumberFormatException e) {
            setErrorMessage("NUMBERFORMAT");
            return false;
        }

        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        cleanUpWizardInfo(wizardInfo);

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CREATE_INTERNALDB;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_DB_MODE+"=remote";
        rawData = rawData+"&"+ConfigConstants.PR_HOST+"="+mRMHostText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_DB_PORT+"="+mRMPortText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_DB_BINDDN+"="+mRMBindAsText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+mRMPasswordText.getText();
        rawData = rawData+"&"+ConfigConstants.PR_DB_NAME+"="+mRMBaseDNText.getText();
   	    wizardInfo.setInternalDBPasswd(mRMPasswordText.getText().trim());
   	    wizardInfo.setDBBindDN(mRMBindAsText.getText().trim());

        startProgressStatus();
        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CONNECTDB");

        boolean ready = send(rawData, wizardInfo);

        if (ready) {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_TOKEN_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
            ready = send(rawData, wizardInfo);
        }
        //dlg.setVisible(false);

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

    @Override
    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel instanceIDLbl = makeJLabel("REMOTEHOST");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(instanceIDLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRMHostText = makeJTextField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMHostText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel portNumber = makeJLabel("REMOTEPORT");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(portNumber, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRMPortText = makeJTextField(10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mRMPortText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel mRMBindAsLabel = makeJLabel("REMOTEADMIN");
        //gbc.anchor = gbc.NORTHWEST;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMBindAsLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRMBindAsText = makeJTextField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMBindAsText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel mRMPasswordLabel = makeJLabel("REMOTEPWD");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMPasswordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRMPasswordText = makeJPasswordField(30);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMPasswordText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel mRMBaseDNLabel = makeJLabel("REMOTEBASEDN");
        //gbc.anchor = gbc.NORTHWEST;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMBaseDNLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRMBaseDNText = makeJTextField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRMBaseDNText, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.setDBCreated(ConfigConstants.TRUE);
        wizardInfo.setDBCreateNow(ConfigConstants.FALSE);
        wizardInfo.setConnectDBDone(ConfigConstants.TRUE);
    }
}

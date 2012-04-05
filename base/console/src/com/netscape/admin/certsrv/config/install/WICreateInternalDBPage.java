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
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICreateInternalDBPage extends WizardBasePanel implements IWizardPanel {
    private Color mActiveColor;
    private JTextField mPortText, mBindAsText, mInstanceIDText;
    private JTextField mRemoteHostText, mRemotePortText, mRemoteBaseDNText;
    private JTextField mRemoteBindAsText,mRemotePasswordText, mRemoteDatabaseText;
    private JPasswordField mPasswordText, mPasswordAgainText;
    private JLabel mBindAsLabel, mPasswordLabel, mPasswordAgainLabel;
    private JComboBox mVersionBox;
    private JCheckBox mEnable, mSchema;
    private JRadioButton mLocal, mRemote;
    private static final String PANELNAME = "CREATEINTERNALDBWIZARD";
    private static final String HELPINDEX =
      "install-internaldb-configuration-wizard-help";
    private static final String EMPTYSTR = "                    ";

    WICreateInternalDBPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WICreateInternalDBPage(JDialog parent, JFrame adminFrame) {
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
            enableLocalDB(mEnable.isSelected());
            enableRemoteDB(mEnable.isSelected());
            mLocal.setEnabled(mEnable.isSelected());
            mRemote.setEnabled(mEnable.isSelected());
        } else if (e.getSource().equals(mLocal)) {
            enableLocalDB(mEnable.isSelected());
            enableRemoteDB(mEnable.isSelected());
        } else if (e.getSource().equals(mRemote)) {
            enableLocalDB(mEnable.isSelected());
            enableRemoteDB(mEnable.isSelected());
        }
    }

    private void enableLocalDB(boolean e)
    {
        Color c;
        if (e) {
            if (mLocal.isSelected())
                c = mActiveColor;
            else
                c = getBackground();
        } else {
            c = getBackground();
        }
        mPortText.setEditable(e);
        mPortText.setEnabled(e);
        mPortText.setBackground(c);
        mBindAsText.setEditable(e);
        mBindAsText.setEnabled(e);
        mBindAsText.setBackground(c);
        mInstanceIDText.setEditable(e);
        mInstanceIDText.setEnabled(e);
        mInstanceIDText.setBackground(c);
        mPasswordText.setEditable(e);
        mPasswordText.setEnabled(e);
        mPasswordText.setBackground(c);
        mPasswordAgainText.setEditable(e);
        mPasswordAgainText.setEnabled(e);
        mPasswordAgainText.setBackground(c);
    }

    private void enableRemoteDB(boolean e) {
        Color c;
        if (e) {
            if (mRemote.isSelected())
                c = mActiveColor;
            else
                c = getBackground();
        } else {
            c = getBackground();
        }
        mRemoteHostText.setEditable(e);
        mRemoteHostText.setEnabled(e);
        mRemoteHostText.setBackground(c);
        mRemotePortText.setEditable(e);
        mRemotePortText.setEnabled(e);
        mRemotePortText.setBackground(c);
        mRemoteBaseDNText.setEditable(e);
        mRemoteBaseDNText.setEnabled(e);
        mRemoteBaseDNText.setBackground(c);
        mRemoteBindAsText.setEditable(e);
        mRemoteBindAsText.setEnabled(e);
        mRemoteBindAsText.setBackground(c);
        mRemotePasswordText.setEditable(e);
        mRemotePasswordText.setEnabled(e);
        mRemotePasswordText.setBackground(c);
        mRemoteDatabaseText.setEditable(e);
        mRemoteDatabaseText.setEnabled(e);
        mRemoteDatabaseText.setBackground(c);
        mSchema.setEnabled(e);
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning() && wizardInfo.isUpdateDBInfoDone())
            return false;
        if (wizardInfo.isCloning() && !wizardInfo.isCreateDBDone()) {
            setBorder(makeTitledBorder(PANELNAME));
            mEnable.setSelected(true);
            mInstanceIDText.setText(wizardInfo.getCloneDBName());
            mPortText.setText(""+wizardInfo.getNextAvailPort());
            mBindAsText.setText(wizardInfo.getDBBindDN());
            mPasswordText.setText("");
            mPasswordAgainText.setText("");
            mRemoteBaseDNText.setText("o=netscapeCertificateServer");
            mRemoteDatabaseText.setText("userRoot");
            mRemoteBindAsText.setText("cn=directory manager");
            enableLocalDB(mEnable.isSelected());
            enableRemoteDB(mEnable.isSelected());
            mLocal.setEnabled(mEnable.isSelected());
            mRemote.setEnabled(mEnable.isSelected());
            return true;
        }

        return false;
    }

    public boolean validatePanel() {
        if (!mEnable.isSelected())
            return true;
        if (mLocal.isSelected()) {
            String passwd = mPasswordText.getText().trim();
            String passwdAgain = mPasswordAgainText.getText().trim();
            String instanceId = mInstanceIDText.getText().trim();
            String bindAs = mBindAsText.getText().trim();
            String port = mPortText.getText().trim();

            if (instanceId.equals("") || bindAs.equals("") ||
              port.equals("")) {
                setErrorMessage("BLANKFIELD");
                return false;
            }

            if (passwd.equals("") || passwdAgain.equals("")) {
                setErrorMessage("BLANKPASSWD");
                return false;
            }
            if (!passwd.equals(passwdAgain)) {
                setErrorMessage("NOTSAMEPASSWD");
                return false;
            }

            try {
                Integer num = new Integer(mPortText.getText().trim());
            } catch (NumberFormatException e) {
                setErrorMessage("NUMBERFORMAT");
                return false;
            }
        } else {
            String host = mRemoteHostText.getText().trim();
            String port = mRemotePortText.getText().trim();
            String baseDN = mRemoteBaseDNText.getText().trim();
            String bindAs = mRemoteBindAsText.getText().trim();
            String passwd = mRemotePasswordText.getText().trim();
            String dbname = mRemoteDatabaseText.getText().trim();
            if (host.equals("") || port.equals("") || bindAs.equals("") ||
              baseDN.equals("") || dbname.equals("")) {
                setErrorMessage("BLANKFIELD");
                return false;
            }
            if (passwd.equals("")) {
                setErrorMessage("BLANKPASSWD");
                return false;
            }
            try {
                Integer num = new Integer(port);
            } catch (NumberFormatException e) {
                setErrorMessage("NUMBERFORMAT");
                return false;
            }
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = "";
        if (!mEnable.isSelected()) {
            rawData = rawData+ConfigConstants.TASKID+"="+TaskId.TASK_UPDATE_DB_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            boolean ready = send(rawData, wizardInfo);
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

        if (mRemote.isSelected()) {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_ADD_DBSCHEMA_INDEXES;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            rawData = rawData+"&"+ConfigConstants.PR_HOST+"="+mRemoteHostText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_DB_PORT+"="+mRemotePortText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_DB_BINDDN+"="+mRemoteBindAsText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+mRemotePasswordText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_DB_NAME+"="+mRemoteBaseDNText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_LDAP_DB_NAME+"="+mRemoteDatabaseText.getText().trim();
            rawData = rawData+"&"+ConfigConstants.PR_DB_SCHEMA+"="+mSchema.isSelected();
            rawData = rawData+"&"+ConfigConstants.PR_DB_MODE+"=remote";
        } else {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CREATE_INTERNALDB;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            rawData = rawData+"&"+ConfigConstants.PR_IS_CLONEDDB_CREATED+"=true";
            rawData = rawData+"&"+ConfigConstants.PR_DB_MODE+"=local";
            rawData = rawData+"&"+ConfigConstants.PR_DB_PORT+"="+mPortText.getText();
            rawData = rawData+"&"+ConfigConstants.PR_DB_BINDDN+"="+mBindAsText.getText();
            rawData = rawData+"&"+ConfigConstants.PR_DB_NAME+"="+mInstanceIDText.getText();
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+mPasswordText.getText();
   	    wizardInfo.setInternalDBPasswd(mPasswordText.getText().trim());
   	    wizardInfo.setDBBindDN(mBindAsText.getText().trim());
   	    wizardInfo.setDBName(mInstanceIDText.getText().trim());
        }

        startProgressStatus();
        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CREATEDB");

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

        CMSAdminUtil.resetGBC(gbc);
        mLocal = makeJRadioButton("LOCAL", true);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 2*COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(mLocal, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel instanceIDLbl = makeJLabel("INSTANCEID");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(instanceIDLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mInstanceIDText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mInstanceIDText, gbc);
        mActiveColor = mInstanceIDText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        JLabel portNumber = makeJLabel("PORT");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(portNumber, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mPortText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mBindAsLabel = makeJLabel("ADMIN");
        //gbc.anchor = gbc.NORTHWEST;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 2*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mBindAsLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mBindAsText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mBindAsText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordLabel = makeJLabel("PWD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainLabel = makeJLabel("PWDAGAIN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainText = makeJPasswordField(30);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemote = makeJRadioButton("REMOTE", false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 2*COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(mRemote, gbc);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(mLocal);
        buttonGroup.add(mRemote);

        CMSAdminUtil.resetGBC(gbc);
        JLabel hostLbl = makeJLabel("HOST");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(hostLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemoteHostText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRemoteHostText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel portNumber1 = makeJLabel("PORT");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(portNumber1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemotePortText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mRemotePortText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel baseDNLbl = makeJLabel("BASEDN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(baseDNLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemoteBaseDNText = makeJTextField(30);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mRemoteBaseDNText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel bindAsLabel = makeJLabel("ADMIN");
        //gbc.anchor = gbc.NORTHWEST;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 2*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(bindAsLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemoteBindAsText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRemoteBindAsText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordLabel = makeJLabel("PWD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemotePasswordText = makeJPasswordField(30);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRemotePasswordText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel databaseLabel = makeJLabel("DNAME");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 3*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(databaseLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRemoteDatabaseText = makeJTextField(30);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mRemoteDatabaseText, gbc);

        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(dummy1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSchema = makeJCheckBox("SCHEMA", true);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mSchema, gbc);

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
        wizardInfo.setDBCreated(ConfigConstants.TRUE);
        wizardInfo.setDBCreateNow(ConfigConstants.FALSE);
        wizardInfo.setCreateDBDone(ConfigConstants.TRUE);

        if (mEnable.isSelected())
            wizardInfo.setCloneDBCreated("true");
        else {
            wizardInfo.setUpdateDBInfoDone(ConfigConstants.TRUE);
            wizardInfo.setCloneDBCreated("false");
        }
    }
}

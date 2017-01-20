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
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Migration page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIMigrationPage extends WizardBasePanel implements IWizardPanel, ItemListener {
    private JLabel mTransportLbl, mDBLbl;
    private JPasswordField mTransportPassword, mDBPassword;
    private JLabel mCAPasswdLbl, mCAPasswdAgainLbl, mCASOPLbl;
    private JPasswordField mCAPassword, mCAPasswordAgain, mCASOPPassword;
    private JLabel mSSLPasswdLbl, mSSLPasswdAgainLbl, mSSLSOPLbl;
    private JPasswordField mSSLPassword, mSSLPasswordAgain, mSSLSOPPassword;
    private JLabel mPathLbl, mCATokenHeading, mSSLTokenHeading;
    private JLabel mCATokenLbl, mSSLTokenLbl;
    private JTextField mPathText;
    private JComboBox mCATokenBox, mSSLTokenBox;
    private String[] mTokenInitialized;
    private String[] mTokenLogin;
    private Color mActiveColor;
    private JLabel mLogonInitCATokenLbl, mLogonInitSSLTokenLbl;
    private String mHelpIndex;
    private InstallWizardInfo mWizardInfo;
    private static final String PANELNAME = "MIGRATIONWIZARD";
    private static final String CAHELPINDEX =
      "install-ca-migration-configuration-wizard-help";
    private static final String CAKRAHELPINDEX =
      "install-cakra-migration-configuration-wizard-help";

    WIMigrationPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIMigrationPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;
        if (!mWizardInfo.isMigrationEnable() || !mWizardInfo.isCAInstalled() ||
          mWizardInfo.isMigrationDone())
            return false;
        setBorder(makeTitledBorder(PANELNAME));
        initializeTokenBox(mCATokenBox);

        if (mSSLTokenBox.getItemCount() > 0)
            mSSLTokenBox.removeAllItems();
        for (int i=0; i<mCATokenBox.getItemCount(); i++) {
            String str = (String)mCATokenBox.getItemAt(i);
            mSSLTokenBox.addItem(str);
        }
        int index = mCATokenBox.getSelectedIndex();
        mWizardInfo.setMigrateCACertTokenName((String)mCATokenBox.getSelectedItem());
        enableFields(index, mLogonInitCATokenLbl, mCAPasswdLbl, mCAPassword,
          mCAPasswdAgainLbl, mCAPasswordAgain, mCASOPLbl, mCASOPPassword);

        index = mSSLTokenBox.getSelectedIndex();
        mWizardInfo.setMigrateSSLCertTokenName((String)mSSLTokenBox.getSelectedItem());
        enableFields(index, mLogonInitSSLTokenLbl, mSSLPasswdLbl, mSSLPassword,
          mSSLPasswdAgainLbl, mSSLPasswordAgain, mSSLSOPLbl, mSSLSOPPassword);

        mCATokenBox.addItemListener(this);
        mSSLTokenBox.addItemListener(this);
        enablePasswordFields();

        if (mWizardInfo.isCAInstalled() && mWizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;

        return true;
    }

    private void initializeTokenBox(JComboBox tokenBox) {
        if (tokenBox.getItemCount() > 0)
            tokenBox.removeAllItems();

        String tokenList = mWizardInfo.getTokensList();
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ":");
        int count = tokenizer.countTokens();
        while (tokenizer.hasMoreTokens()) {
            tokenBox.addItem((String)tokenizer.nextToken());
        }

        String initializedList = mWizardInfo.getTokensInit();
        tokenizer = new StringTokenizer(initializedList, ":");
        int i=0;
        mTokenInitialized = new String[count];
        while (tokenizer.hasMoreElements()) {
            mTokenInitialized[i] = (String)tokenizer.nextToken();
            i++;
        }

        String loginList = mWizardInfo.getTokensLogin();
        tokenizer = new StringTokenizer(loginList, ":");
        i=0;
        mTokenLogin = new String[count];
        while (tokenizer.hasMoreElements()) {
            mTokenLogin[i] = (String)tokenizer.nextToken();
            i++;
        }
    }

    public boolean validatePanel() {
        int caindex = mCATokenBox.getSelectedIndex();
        boolean status = false;

        if (caindex > 0) {
            status = validateHardwareToken(caindex, mCAPassword, mCAPasswordAgain,
              mCASOPPassword);
        } else {
            status = validateInternalToken(caindex, mCAPassword, mCAPasswordAgain);
        }

        if (!status)
            return false;

        int sslindex = mSSLTokenBox.getSelectedIndex();
        if (sslindex != caindex) {
            if (sslindex > 0) {
                status = validateHardwareToken(sslindex, mSSLPassword, mSSLPasswordAgain,
                  mSSLSOPPassword);
            } else {
                status = validateInternalToken(sslindex, mSSLPassword, mSSLPasswordAgain);
            }
        }

        return status;
    }

    private boolean validateHardwareToken(int index, JPasswordField passwdField,
      JPasswordField passwdAgainField, JPasswordField sopPasswdField) {
        String caPasswd = mCAPassword.getText().trim();
        String caPasswdAgain = mCAPasswordAgain.getText().trim();
        String sslPasswd = mSSLPassword.getText().trim();
        String sslPasswdAgain = mSSLPasswordAgain.getText().trim();
        String sopPasswd = sopPasswdField.getText();
        if (mTokenLogin[index].equals(ConfigConstants.TRUE)) {
            return true;
        }

        if (mTokenInitialized[index].equals(ConfigConstants.TRUE)) {
            if (caPasswd.equals("")) {
            //if (caPasswd.equals("") || sopPasswd.equals("")) {
                setErrorMessage("BLANKPASSWD");
                return false;
            }
            return true;
        }

        if (caPasswd.equals("") || caPasswdAgain.equals("") || sopPasswd.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }
        if (!caPasswd.equals(caPasswdAgain)) {
            setErrorMessage("NOTSAMEPASSWD");
            return false;
        }
        return true;
    }

    private boolean validateInternalToken(int index, JPasswordField passwdField,
      JPasswordField passwdAgainField) {
        String passwd = passwdField.getText();
        String passwdAgain = passwdAgainField.getText();
        if (mTokenLogin[index].equals(ConfigConstants.TRUE)) {
            return true;
        }

        if (mTokenInitialized[index].equals(ConfigConstants.TRUE)) {
            if (passwd.equals("")) {
                setErrorMessage("BLANKPASSWD");
                return false;
            }
            return true;
        }

        if (passwd.equals("") || passwdAgain.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }
        if (!passwd.equals(passwdAgain)) {
            setErrorMessage("NOTSAMEPASSWD");
            return false;
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        Hashtable data = new Hashtable();
        String caTokenName = "";
        String sslTokenName = "";
        if (mCATokenBox.getSelectedIndex() == 0) {
            caTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        } else {
            caTokenName = (String)mCATokenBox.getSelectedItem();
        }
        if (mSSLTokenBox.getSelectedIndex() == 0) {
            sslTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        } else {
            sslTokenName = (String)mSSLTokenBox.getSelectedItem();
        }

        mWizardInfo.setCATokenName(caTokenName);
        mWizardInfo.setSSLTokenName(sslTokenName);
        mWizardInfo.setMigrationOutputPath(mPathText.getText().trim());
        //mWizardInfo.setInternalDBPasswd(mDBPassword.getText().trim());
        mWizardInfo.setMigrationPasswd(mTransportPassword.getText().trim());
        mWizardInfo.setSigningKeyMigrationToken(caTokenName);
        mWizardInfo.setSigningKeyMigrationPasswd(mCAPassword.getText().trim());
        if (mCATokenBox.getSelectedIndex() > 0) {
            mWizardInfo.setSigningKeyMigrationSOPPasswd(mCASOPPassword.getText().trim());
            data.put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_SOPPASSWD,
              mWizardInfo.getSigningKeyMigrationSOPPasswd());
        }
        mWizardInfo.setSSLKeyMigrationToken(sslTokenName);

        if (caTokenName.equals(sslTokenName))
            mWizardInfo.setSSLKeyMigrationPasswd(mCAPassword.getText().trim());
        else
            mWizardInfo.setSSLKeyMigrationPasswd(mSSLPassword.getText().trim());

        if (mSSLTokenBox.getSelectedIndex() > 0) {
            mWizardInfo.setSSLKeyMigrationSOPPasswd(mSSLSOPPassword.getText().trim());
            data.put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_SOPPASSWD,
              mWizardInfo.getSSLKeyMigrationSOPPasswd());
        }
        ConsoleInfo consoleInfo = mWizardInfo.getAdminConsoleInfo();
        CMSConfigCert configCertCgi = new CMSConfigCert();
        configCertCgi.initialize(mWizardInfo);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
          consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));

        data.put(ConfigConstants.TASKID, TaskId.TASK_MIGRATION);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
        if (mWizardInfo.isMigrationEnable())
            data.put(ConfigConstants.PR_ENABLE_MIGRATION, ConfigConstants.TRUE);
        else
            data.put(ConfigConstants.PR_ENABLE_MIGRATION, ConfigConstants.FALSE);
        data.put(ConfigConstants.PR_OUTPUT_PATH,
          mWizardInfo.getMigrationOutputPath());
        if (mWizardInfo.getInternalDBPasswd() != null)
            data.put(ConfigConstants.PR_DB_PWD,
              mWizardInfo.getInternalDBPasswd());
        data.put(ConfigConstants.PR_MIGRATION_PASSWORD,
          mWizardInfo.getMigrationPasswd());
        data.put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN,
          mWizardInfo.getSigningKeyMigrationToken());
        data.put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_PASSWD,
          mWizardInfo.getSigningKeyMigrationPasswd());
        data.put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN,
          mWizardInfo.getSSLKeyMigrationToken());
        data.put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_PASSWD,
          mWizardInfo.getSSLKeyMigrationPasswd());

        startProgressStatus();
        boolean ready = configCertCgi.configCert(data);
        endProgressStatus();

        mWizardInfo.put("TOKEN:"+caTokenName, mCAPassword.getText().trim());
        mWizardInfo.put("TOKEN:"+sslTokenName,
          mSSLPassword.getText().trim());

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

    public void itemStateChanged(ItemEvent e) {
        super.itemStateChanged(e);
        int index = 0;
        if (e.getSource().equals(mCATokenBox)) {
            index = mCATokenBox.getSelectedIndex();
            mWizardInfo.setMigrateCACertTokenName((String)mCATokenBox.getSelectedItem());
            enableFields(index, mLogonInitCATokenLbl, mCAPasswdLbl, mCAPassword,
              mCAPasswdAgainLbl, mCAPasswordAgain, mCASOPLbl, mCASOPPassword);
            enablePasswordFields();
        } else if (e.getSource().equals(mSSLTokenBox)) {
            index = mSSLTokenBox.getSelectedIndex();
            mWizardInfo.setMigrateSSLCertTokenName((String)mSSLTokenBox.getSelectedItem());
            enableFields(index, mLogonInitSSLTokenLbl, mSSLPasswdLbl, mSSLPassword,
              mSSLPasswdAgainLbl, mSSLPasswordAgain, mSSLSOPLbl, mSSLSOPPassword);
            enablePasswordFields();
        }
    }

    private void enableFields(int index, JLabel logonInitLbl, JLabel passwdLbl,
      JPasswordField passwd, JLabel passwdAgainLbl, JPasswordField passwdAgain,
      JLabel sopLbl, JPasswordField sopPasswd) {
        if (mTokenLogin[index].equals(ConfigConstants.TRUE)) {
            logonInitLbl.setText("");
            enableFields(logonInitLbl, null, false, null);
            enableFields(sopLbl, sopPasswd, false, getBackground());
            enableFields(passwdLbl, passwd, false, getBackground());
            enableFields(passwdAgainLbl, passwdAgain, false, getBackground());
        } else {
            if (mTokenInitialized[index].equals(ConfigConstants.TRUE)) {
                String str = mResource.getString(PANELNAME+"_LABEL_LOGIN_LABEL");
                logonInitLbl.setText(str);
                enableFields(logonInitLbl, null, true, null);
                enableFields(passwdAgainLbl, passwdAgain, false, getBackground());
                enableFields(passwdLbl, passwd, true, mActiveColor);
                enableFields(sopLbl, sopPasswd, false, getBackground());
            } else {
                String str = mResource.getString(PANELNAME+"_LABEL_INITIALIZE_LABEL")
;
                logonInitLbl.setText(str);
                enableFields(logonInitLbl, null, true, null);
                enableFields(logonInitLbl, null, true, null);
                enableFields(passwdAgainLbl, passwdAgain, true, mActiveColor);
                enableFields(passwdLbl, passwd, true, mActiveColor);
                if (index == 0) {
                    enableFields(sopLbl, sopPasswd, false, getBackground());
                } else {
                    enableFields(sopLbl, sopPasswd, true, mActiveColor);
                }
            }
        }
    }

    protected void enableFields(JComponent comp1, JTextComponent comp2,
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

    protected void enablePasswordFields() {
        String caTokenStr = (String)mCATokenBox.getSelectedItem();
        String sslTokenStr = (String)mSSLTokenBox.getSelectedItem();
        if (caTokenStr.equals(sslTokenStr)) {
            enableFields(mSSLPasswdLbl, mSSLPassword, false, getBackground());
            enableFields(mSSLPasswdAgainLbl, mSSLPasswordAgain, false, getBackground());
        } else {
            enableFields(mSSLPasswdLbl, mSSLPassword, true, mActiveColor);
            enableFields(mSSLPasswdAgainLbl, mSSLPasswordAgain, true, mActiveColor);
        }
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        JTextArea desc =  createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "MIGRATIONWIZARD_TEXT_DESC_LABEL"), 80), 1, 80);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);
*/

        CMSAdminUtil.resetGBC(gbc);
        mPathLbl = makeJLabel("PATH");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mPathLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPathText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPathText, gbc);

        mTransportLbl = makeJLabel("TRANSPORTPASSWORD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mTransportLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mTransportPassword = makeJPasswordField(20);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTransportPassword, gbc);
        mActiveColor = mTransportPassword.getBackground();

/*
        mDBLbl = makeJLabel("DBPASSWORD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mDBLbl, gbc);

        mDBPassword = makeJPasswordField(20);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mDBPassword, gbc);
*/

        JPanel panel1 = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel1.setLayout(gb1);

        mCATokenHeading = makeJLabel("SELECTCATOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel1.add(mCATokenHeading, gbc);

        mCATokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        panel1.add(mCATokenLbl, gbc);

        mCATokenBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        //gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel1.add(mCATokenBox, gbc);

        JTextArea dummy1 = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        panel1.add(dummy1, gbc);

        JPanel panel1a = new JPanel();
        GridBagLayout gb1a = new GridBagLayout();
        panel1a.setLayout(gb1a);

        mLogonInitCATokenLbl = new JLabel("Initialize the selected token:");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, 0, COMPONENT_SPACE);
        panel1a.add(mLogonInitCATokenLbl, gbc);

        mCAPasswdLbl = makeJLabel("PASSWD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel1a.add(mCAPasswdLbl, gbc);

        mCAPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel1a.add(mCAPassword, gbc);

        mCAPasswdAgainLbl = makeJLabel("PASSWDAGAIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel1a.add(mCAPasswdAgainLbl, gbc);

        mCAPasswordAgain = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel1a.add(mCAPasswordAgain, gbc);

        mCASOPLbl = makeJLabel("SOP");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel1a.add(mCASOPLbl, gbc);

        mCASOPPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel1a.add(mCASOPPassword, gbc);

        JPanel panel2 = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        panel2.setLayout(gb2);

        mSSLTokenHeading = makeJLabel("SELECTSSLTOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2.add(mSSLTokenHeading, gbc);

        mSSLTokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        panel2.add(mSSLTokenLbl, gbc);

        mSSLTokenBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        //gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2.add(mSSLTokenBox, gbc);

        JTextArea dummy1a = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        panel2.add(dummy1a, gbc);

        JPanel panel2a = new JPanel();
        GridBagLayout gb2a = new GridBagLayout();
        panel2a.setLayout(gb2a);

        mLogonInitSSLTokenLbl = new JLabel("Initialize the SSL token");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, 0, COMPONENT_SPACE);
        panel2a.add(mLogonInitSSLTokenLbl, gbc);

        mSSLPasswdLbl = makeJLabel("PASSWD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel2a.add(mSSLPasswdLbl, gbc);

        mSSLPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2a.add(mSSLPassword, gbc);

        mSSLPasswdAgainLbl = makeJLabel("PASSWDAGAIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel2a.add(mSSLPasswdAgainLbl, gbc);

        mSSLPasswordAgain = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2a.add(mSSLPasswordAgain, gbc);

        mSSLSOPLbl = makeJLabel("SOP");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2a.add(mSSLSOPLbl, gbc);

        mSSLSOPPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2a.add(mSSLSOPPassword, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        add(panel1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        add(panel1a, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        add(panel2, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        add(panel2a, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dumLbl = new JLabel("");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(dumLbl, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

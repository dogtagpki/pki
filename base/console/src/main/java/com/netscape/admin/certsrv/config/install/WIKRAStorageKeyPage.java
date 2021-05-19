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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.StringTokenizer;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.task.CMSConfigCert;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;
import com.netscape.management.client.console.ConsoleInfo;

/**
 * Install KRA storage key.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRAStorageKeyPage extends WizardBasePanel implements IWizardPanel {
    private String mHelpIndex;
    private static final String PANELNAME = "INSTALLKRASTORAGEKEYWIZARD";
    private static final String KRAHELPINDEX =
      "install-kra-storagekey-wizard-help";
    private static final String CAKRAHELPINDEX =
      "install-cakra-storagekey-wizard-help";
    private static final String RAKRAHELPINDEX =
      "install-rakra-storagekey-wizard-help";

    protected JComboBox<String> mKeyTypeBox, mKeyLengthBox, mDSAKeyLengthBox, mTokenBox;
    protected JPasswordField mPassword, mPasswordAgain, mSOPPassword;
    protected JLabel keyTypeLbl, keyLengthCustomText, keyLengthLbl, unitLbl,
      keyLengthCustomLbl, unit1Lbl, mTokenLbl;
    protected JLabel mPasswdLbl, mPasswdAgainLbl, mSOPLbl;
    protected JCheckBox mHardwareSplit;
    protected String[] mTokenInitialized;
    protected String[] mTokenLogin;
    private Color mActiveColor;

    WIKRAStorageKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIKRAStorageKeyPage(JDialog parent, JFrame adminFrame) {
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
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning())
            return false;
        if (!wizardInfo.isKRAInstalled() || wizardInfo.isKRANMSchemeDone())
            return false;
        setBorder(makeTitledBorder(PANELNAME));

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

       wizardInfo = (InstallWizardInfo)info;
       setBorder(makeTitledBorder(mPanelName));
       if (mTokenBox.getItemCount() > 0) {
           mTokenBox.removeAllItems();
       }

       String tokenList = wizardInfo.getTokensList();
       StringTokenizer tokenizer = new StringTokenizer(tokenList, ":");
       int count = tokenizer.countTokens();
       while (tokenizer.hasMoreTokens()) {
           mTokenBox.addItem(tokenizer.nextToken());
       }

       String initializedList = wizardInfo.getTokensInit();
       tokenizer = new StringTokenizer(initializedList, ":");
       int i=0;
       mTokenInitialized = new String[count];
       while (tokenizer.hasMoreElements()) {
           mTokenInitialized[i] = tokenizer.nextToken();
           i++;
       }

       String loginList = wizardInfo.getTokensLogin();
       tokenizer = new StringTokenizer(loginList, ":");
       i=0;
       mTokenLogin = new String[count];
       while (tokenizer.hasMoreElements()) {
           mTokenLogin[i] = tokenizer.nextToken();
           i++;
       }

       //mTokenBox.setSelectedIndex(0);
       mTokenBox.addItemListener(this);

        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
      int index = mTokenBox.getSelectedIndex();
      if (index > 0) {
        mPassword.setEnabled(true);
        mPassword.setBackground(mActiveColor);
      } else {
        // Internal Token
        mPassword.setEnabled(false);
        mPassword.setBackground(getBackground());
      }
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
		InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
		ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
		CMSConfigCert configCertCgi = new CMSConfigCert();
		configCertCgi.initialize(wizardInfo);

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_STORAGE_KEY;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        wizardInfo.setKeyLength((String)mKeyLengthBox.getSelectedItem());
        rawData = rawData+"&"+ConfigConstants.PR_KEY_LEN+"="+wizardInfo.getKeyLength();
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_NAME+"="+(String)mTokenBox.getSelectedItem();
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_PASSWD+"="+
          mPassword.getText().trim();
        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

        return ready;
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        JPanel panel2 = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        panel2.setLayout(gb3);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel2, gbc);

        JTextArea selectTokenLbl = createTextArea(mResource.getString(
          mPanelName+"_LABEL_SELECTTOKEN_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,0);
        panel.add(selectTokenLbl, gbc);

        JLabel tokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        gbc.fill = GridBagConstraints.NONE;
        panel.add(tokenLbl, gbc);

        mTokenBox = new JComboBox<>();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel.add(mTokenBox, gbc);
        mTokenBox.addActionListener(this);

        JTextArea dummy2 = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        panel.add(dummy2, gbc);

        mTokenLbl = new JLabel("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel2.add(mTokenLbl, gbc);

        mPasswdLbl = makeJLabel("PASSWD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel2.add(mPasswdLbl, gbc);

        mPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2.add(mPassword, gbc);
        mActiveColor = mPassword.getBackground();

/**
        mPasswdAgainLbl = makeJLabel("PASSWDAGAIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel2.add(mPasswdAgainLbl, gbc);

        mPasswordAgain = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2.add(mPasswordAgain, gbc);

        mSOPLbl = makeJLabel("SOP");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2.add(mSOPLbl, gbc);

        mSOPPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
		COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2.add(mSOPPassword, gbc);
 **/

        CMSAdminUtil.resetGBC(gbc);
        JTextArea label = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_HEADING_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        add(label, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel keyLengthLbl = makeJLabel("KEYLENGTH");
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.fill = GridBagConstraints.NONE;
        add(keyLengthLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mKeyLengthBox = makeJComboBox("KEYLENGTH");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mKeyLengthBox, gbc);

/**
       CMSAdminUtil.resetGBC(gbc);
       mHardwareSplit = makeJCheckBox("HARDWARE_SPLIT");
       gbc.anchor = gbc.NORTHWEST;
       //gbc.weightx = 0.0;
       gbc.gridwidth = gbc.REMAINDER;
       gbc.fill = gbc.NONE;
       gbc.insets = new Insets(COMPONENT_SPACE,
         DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,0,COMPONENT_SPACE);
       add(mHardwareSplit, gbc);
        mHardwareSplit.setEnabled(false);
        mHardwareSplit.setSelected(false);
 **/

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy = new JLabel(" ");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

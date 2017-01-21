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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.StringTokenizer;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.text.JTextComponent;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Setup key information for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKeyPage extends WizardBasePanel implements IWizardPanel, ItemListener {
    protected Color mActiveColor;
    protected JComboBox mKeyTypeBox, mKeyLengthBox, mDSAKeyLengthBox, mTokenBox;
    protected JTextField mKeyLengthText;
    protected JPasswordField mPassword, mPasswordAgain, mSOPPassword;
    protected JLabel keyTypeLbl, keyLengthCustomText, keyLengthLbl, unitLbl,
      keyLengthCustomLbl, unit1Lbl, mTokenLbl;
    protected JTextArea keyHeading;
    protected JLabel mPasswdLbl, mPasswdAgainLbl, mSOPLbl;
    private String mPanelName;
    protected String[] mTokenInitialized;
    protected String[] mTokenLogin;
    protected InstallWizardInfo mWizardInfo;
    protected String mHelpIndex;
    protected boolean mIsCAKey;

    WIKeyPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(mPanelName));
        if (mTokenBox.getItemCount() > 0) {
            mTokenBox.removeAllItems();
        }

        String tokenList = mWizardInfo.getTokensList();
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ":");
        int count = tokenizer.countTokens();
        while (tokenizer.hasMoreTokens()) {
            mTokenBox.addItem(tokenizer.nextToken());
        }

        String initializedList = mWizardInfo.getTokensInit();
        tokenizer = new StringTokenizer(initializedList, ":");
        int i=0;
        mTokenInitialized = new String[count];
        while (tokenizer.hasMoreElements()) {
            mTokenInitialized[i] = tokenizer.nextToken();
            i++;
        }

        String loginList = mWizardInfo.getTokensLogin();
        tokenizer = new StringTokenizer(loginList, ":");
        i=0;
        mTokenLogin = new String[count];
        while (tokenizer.hasMoreElements()) {
            mTokenLogin[i] = tokenizer.nextToken();
            i++;
        }

        //mTokenBox.setSelectedIndex(0);
        mTokenBox.addItemListener(this);

        String type = (String)mKeyTypeBox.getSelectedItem();
        if (type.equals("RSA")) {
            mDSAKeyLengthBox.setVisible(false);
            mKeyLengthBox.setVisible(true);
        } else {
            mKeyLengthBox.setVisible(false);
            mDSAKeyLengthBox.setVisible(true);
        }

        enableKeyLengthFields();
        return true;
    }

    public boolean validatePanel() {
        int index = mTokenBox.getSelectedIndex();

        if (mKeyLengthText.isEnabled()) {
            String str = mKeyLengthText.getText().trim();
            if (str.equals("")) {
                setErrorMessage("BLANKLEN");
                return false;
            } else {
                try {
                    int num = Integer.parseInt(str);
                    if (num <= 0) {
                        setErrorMessage("INVALIDKEYLEN");
                        return false;
                    }else if (mKeyTypeBox.isVisible()) {
                        String type = (String)mKeyTypeBox.getSelectedItem();
                        if (type.equals("RSA")) {
                            float fraction = num / (float)8.0;
                            int wholeNumber = (int)fraction;
                            if((fraction - wholeNumber)!=0) {
                                setErrorMessage("RSAINVALID");
                                return false;
                            }
                        }else {
                            float fraction = num / (float)64.0;
                            int wholeNumber = (int)fraction;
                            if(num < 512 || num > 1024 || (fraction - wholeNumber)!=0){
                                setErrorMessage("DSAINVALID");
                                return false;
                            }
                        }
                    }
                } catch (NumberFormatException e) {
                    setErrorMessage("NONINTEGER");
                    return false;
                }
            }
        }

        if (index > 0)
            return validateHardwareToken(index);
        else
            return validateInternalToken(index);
    }

    private boolean validateHardwareToken(int index) {
        String passwd = mPassword.getText();
        String passwdAgain = mPasswordAgain.getText();
        String sopPasswd = mSOPPassword.getText();
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

        if (passwd.equals("") || passwdAgain.equals("") || sopPasswd.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }
        if (!passwd.equals(passwdAgain)) {
            setErrorMessage("NOTSAMEPASSWD");
            return false;
        }
        return true;
    }

    private boolean validateInternalToken(int index) {
        String passwd = mPassword.getText();
        String passwdAgain = mPasswordAgain.getText();
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
        mWizardInfo = (InstallWizardInfo)info;

        String customLen = "";
        if (mKeyLengthText.isEnabled())
            customLen = mKeyLengthText.getText();

        if (customLen != null && (!customLen.trim().equals(""))) {
            mWizardInfo.put(ConfigConstants.PR_KEY_LEN, customLen);
        } else {
            if (mKeyLengthBox.isVisible()) {
                mWizardInfo.put(ConfigConstants.PR_KEY_LEN,
                  mKeyLengthBox.getSelectedItem());
            } else if (mDSAKeyLengthBox.isVisible()) {
                mWizardInfo.put(ConfigConstants.PR_KEY_LEN,
                  mDSAKeyLengthBox.getSelectedItem());
            }
        }

        if (mIsCAKey) {
            mWizardInfo.put(ConfigConstants.PR_CA_KEYTYPE, mKeyTypeBox.getSelectedItem());
            mWizardInfo.put(ConfigConstants.PR_CA_KEYTYPE, mKeyTypeBox.getSelectedItem());
        }

        mWizardInfo.put(ConfigConstants.PR_KEY_TYPE, mKeyTypeBox.getSelectedItem());

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_INIT_TOKEN;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_NAME+"="+(String)mTokenBox.getSelectedItem();
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_PASSWD+"="+mPassword.getText().trim();
        String sop = mSOPPassword.getText().trim();
        if (sop != null) {
            rawData = rawData+"&"+ConfigConstants.PR_TOKEN_SOP+"="+sop;
        }
        rawData = rawData+"&"+ConfigConstants.PR_KEY_LEN+"="+mWizardInfo.getKeyLength();
        rawData = rawData+"&"+ConfigConstants.PR_KEY_TYPE+"="+mWizardInfo.getKeyType();
        rawData = rawData+"&"+ConfigConstants.PR_CERTIFICATE_TYPE+"="+mWizardInfo.getCertType();

        startProgressStatus();
//        CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "INITTOKEN");

        boolean ready = send(rawData, mWizardInfo);

        if (ready) {
            rawData = rawData+"&"+ConfigConstants.TASKID+"="+TaskId.TASK_TOKEN_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
            ready = send(rawData, mWizardInfo);
        }

        if (ready) {
            rawData = rawData+"&"+ConfigConstants.TASKID+"="+TaskId.TASK_CHECK_KEYLENGTH;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            ready = send(rawData, mWizardInfo);
        }

        //dlg.setVisible(false);

        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
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

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        JPanel panel2 = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        panel2.setLayout(gb3);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel2, gbc);

        JTextArea selectTokenLbl = createTextArea(mResource.getString(
          mPanelName+"_LABEL_SELECTTOKEN_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,0);
        panel.add(selectTokenLbl, gbc);

        JLabel tokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        panel.add(tokenLbl, gbc);

        mTokenBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel.add(mTokenBox, gbc);

        JTextArea dummy2 = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        panel.add(dummy2, gbc);

        mTokenLbl = new JLabel("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel2.add(mTokenLbl, gbc);

        mPasswdLbl = makeJLabel("PASSWD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0,
          COMPONENT_SPACE);
        panel2.add(mPasswdLbl, gbc);

        mPassword = new JPasswordField();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel2.add(mPassword, gbc);

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
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel2.add(mSOPPassword, gbc);

        keyHeading = createTextArea(mResource.getString(
          mPanelName+"_LABEL_KEY_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(keyHeading, gbc);

        keyTypeLbl = makeJLabel("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(keyTypeLbl, gbc);

        mKeyTypeBox = makeJComboBox("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mKeyTypeBox, gbc);

        keyLengthLbl = makeJLabel("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(keyLengthLbl, gbc);

        mDSAKeyLengthBox = makeJComboBox("DSAKEYLENGTH");
        mDSAKeyLengthBox.setVisible(false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mDSAKeyLengthBox, gbc);

        mKeyLengthBox = makeJComboBox("KEYLENGTH");
        mKeyLengthBox.setVisible(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mKeyLengthBox, gbc);

        unitLbl = makeJLabel("UNITS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0,COMPONENT_SPACE, COMPONENT_SPACE);
        add(unitLbl, gbc);

        JPanel panel1 = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        panel1.setLayout(gb2);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, 0, 0);
        add(panel1, gbc);

        keyLengthCustomText = makeJLabel("CUSTOMKEY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel1.add(keyLengthCustomText, gbc);

/*
        keyLengthCustomLbl = makeJLabel("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.fill = gbc.NONE;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,0,COMPONENT_SPACE);
        add(keyLengthCustomLbl, gbc);
*/

        mKeyLengthText = makeJTextField(7);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE, 0);
        panel1.add(mKeyLengthText, gbc);
        mActiveColor = mKeyLengthText.getBackground();

        unit1Lbl = makeJLabel("UNITS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE);
        panel1.add(unit1Lbl, gbc);

        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy1, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        mWizardInfo = (InstallWizardInfo)info;
        String name = (String)mTokenBox.getSelectedItem();
        if (name.equalsIgnoreCase(CryptoUtil.INTERNAL_TOKEN_NAME))
            name = Constants.PR_INTERNAL_TOKEN_NAME;
        mWizardInfo.put(ConfigConstants.PR_TOKEN_NAME, name);
        if (mPassword.isEditable()) {
            // this is used for single signon. The key is the token name with
            // the prefix "TOKEN:" and the value is the token password.
            mWizardInfo.put("TOKEN:"+name, mPassword.getText().trim());
        }

        mTokenBox.removeItemListener(this);
    }

    public void actionPerformed(ActionEvent e) {
    }

    public void itemStateChanged(ItemEvent e){
        //super.itemStateChanged(e);
        if (e.getSource().equals(mTokenBox)) {
            JComboBox c = (JComboBox)(e.getSource());
            if (c.getItemCount() > 0)
                enableFields();
        } else if (e.getSource().equals(mKeyLengthBox) ||
          e.getSource().equals(mDSAKeyLengthBox)) {
            enableKeyLengthFields();
        } else if (e.getSource().equals(mKeyTypeBox)) {
            String type = (String)mKeyTypeBox.getSelectedItem();
            if (type.equals("RSA")) {
                mDSAKeyLengthBox.setVisible(false);
                mKeyLengthBox.setVisible(true);
            } else {
                mDSAKeyLengthBox.setVisible(true);
                mKeyLengthBox.setVisible(false);
            }
            enableKeyLengthFields();
            CMSAdminUtil.repaintComp(this);
        }
    }

    protected void enableKeyLengthFields() {
        String value = "";
        if (mKeyLengthBox.isVisible())
            value = (String)mKeyLengthBox.getSelectedItem();
        else
            value = (String)mDSAKeyLengthBox.getSelectedItem();

        if (value.equals("Custom")) {
            enableFields(keyLengthCustomText, mKeyLengthText, true, mActiveColor);
            enableFields(unit1Lbl, null, true, mActiveColor);
        } else {
            enableFields(keyLengthCustomText, mKeyLengthText, false,
              getBackground());
            enableFields(unit1Lbl, null, false, getBackground());
        }
    }

    protected void enableFields(JComponent comp1, JTextComponent comp2, boolean enable,
      Color color) {
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


    protected void enableFields() {
        int index = mTokenBox.getSelectedIndex();

        if (mTokenLogin[index].equals(ConfigConstants.TRUE)) {
            mTokenLbl.setText("");
            enableFields(mTokenLbl, null, false, null);
            enableFields(mSOPLbl, mSOPPassword, false, getBackground());
            enableFields(mPasswdLbl, mPassword, false, getBackground());
            enableFields(mPasswdAgainLbl, mPasswordAgain, false, getBackground());
        } else {
            if (mTokenInitialized[index].equals(ConfigConstants.TRUE)) {
                String str = mResource.getString(mPanelName+"_LABEL_LOGIN_LABEL");
                mTokenLbl.setText(str);
                enableFields(mTokenLbl, null, true, null);
                enableFields(mPasswdAgainLbl, mPasswordAgain, false, getBackground());
                enableFields(mPasswdLbl, mPassword, true, mActiveColor);
                enableFields(mSOPLbl, mSOPPassword, false, getBackground());
/*
                if (index == 0) {
                    enableFields(mSOPLbl, mSOPPassword, false, getBackground());
                } else {
                    enableFields(mSOPLbl, mSOPPassword, true, mActiveColor);
                }
*/
            } else {
                String str = mResource.getString(mPanelName+"_LABEL_INITIALIZE_LABEL");
                mTokenLbl.setText(str);
                enableFields(mTokenLbl, null, true, null);
                enableFields(mTokenLbl, null, true, null);
                enableFields(mPasswdAgainLbl, mPasswordAgain, true, mActiveColor);
                enableFields(mPasswdLbl, mPassword, true, mActiveColor);
                if (index == 0) {
                    enableFields(mSOPLbl, mSOPPassword, false, getBackground());
                } else {
                    enableFields(mSOPLbl, mSOPPassword, true, mActiveColor);
                }
            }
        }
    }
}

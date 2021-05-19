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
import java.util.StringTokenizer;

import javax.swing.JComponent;
import javax.swing.JLabel;
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

/**
 * This panel asks for the information of the current internal database.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WITokenLogonPage extends WizardBasePanel implements IWizardPanel {
    protected JTextField mTokenText;
    protected JLabel mPasswordAgainLabel;
    protected JPasswordField mPasswordText, mPasswordAgainText;
    protected String mHelpIndex;
    protected String mPanelName;
    protected JTextArea mDesc;
    protected Color mActiveColor;
    protected String mTokenName;

    WITokenLogonPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        String tokenList = wizardInfo.getTokensList();
        String tokenLoggedIn = wizardInfo.getTokensLogin();
        String tokenInits = wizardInfo.getTokensInit();
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ":");
        StringTokenizer tokenizerLoggedIn = new StringTokenizer(tokenLoggedIn, ":");
        StringTokenizer tokenizerInits = new StringTokenizer(tokenInits, ":");
        int index = 0;
        String loggedIn = "";
        String inits = "";
        while (tokenizer.hasMoreElements()) {
            String token = (String)tokenizer.nextElement();
            loggedIn = (String)tokenizerLoggedIn.nextElement();
            inits = (String)tokenizerInits.nextElement();
            if (token.equalsIgnoreCase(mTokenName)) {
                break;
            }
            index++;
        }

        if (inits.equals(Constants.FALSE)) {
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_INIT_LABEL"));
            enableFields(mPasswordAgainLabel, mPasswordAgainText, true, mActiveColor);
        } else {
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_HEADING_LABEL"));
            enableFields(mPasswordAgainLabel, mPasswordAgainText, false, getBackground());
        }

        mTokenText.setEnabled(false);
        mTokenText.setEditable(false);
        mTokenText.setBackground(getBackground());
        CMSAdminUtil.repaintComp(mTokenText);

        return true;
    }

    @Override
    public boolean validatePanel() {
        String passwd = mPasswordText.getText();
        if (passwd.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }
        if (mPasswordAgainText.isEnabled()) {
          String passwdAgain = mPasswordAgainText.getText();
          if (!passwd.equals(passwdAgain)) {
            setErrorMessage("NOTSAMEPASSWD");
            return false;
          }
        }

        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        cleanUpWizardInfo(wizardInfo);

        String tokenname = mTokenText.getText().trim();
        String pwd = mPasswordText.getText().trim();
        wizardInfo.put("TOKEN:"+tokenname, pwd);

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_INIT_TOKEN;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_NAME+"="+tokenname;
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_PASSWD+"="+pwd;
        rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+Long.valueOf(WizardBasePanel.mSeed);

        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str == null) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        } else {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_TOKEN_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
            ready = send(rawData, wizardInfo);
        }

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

        endProgressStatus();

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

        CMSAdminUtil.resetGBC(gbc);
        mDesc = createTextArea("");
/*
        mDesc = createTextArea(mResource.getString(
          mPanelName+"_TEXT_HEADING_LABEL"));
*/
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mDesc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel tokenLabel = makeJLabel("TOKEN");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(tokenLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mTokenText = makeJTextField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTokenText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordLabel = makeJLabel("PWD");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        // gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordText, gbc);
        mActiveColor = mPasswordText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainLabel = makeJLabel("PWDAGAIN");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainText = makeJPasswordField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        // gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainText, gbc);

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
    }

    protected void enableFields(JComponent comp1, JTextComponent comp2, boolean enable, Color color) {
        comp1.setEnabled(enable);
        comp2.setEnabled(enable);
        comp2.setEditable(enable);
        comp2.setBackground(color);
        CMSAdminUtil.repaintComp(comp1);
        CMSAdminUtil.repaintComp(comp2);
    }
}

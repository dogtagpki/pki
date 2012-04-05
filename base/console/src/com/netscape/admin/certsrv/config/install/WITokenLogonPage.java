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
import java.util.*;
import javax.swing.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

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
    private static final String EMPTYSTR = "                    ";
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

    public boolean isLastPage() {
        return false;
    }

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
        rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+
          (new Long(WizardBasePanel.mSeed).toString());

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

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

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
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDesc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel tokenLabel = makeJLabel("TOKEN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(tokenLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mTokenText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTokenText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordLabel = makeJLabel("PWD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        // gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordText, gbc);
        mActiveColor = mPasswordText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainLabel = makeJLabel("PWDAGAIN");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordAgainText = makeJPasswordField(30);
        gbc.anchor = gbc.NORTHWEST;
        // gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordAgainText, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

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

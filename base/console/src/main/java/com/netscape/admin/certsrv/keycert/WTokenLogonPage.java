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
package com.netscape.admin.certsrv.keycert;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This panel asks for the user to logon to the keycert token  .
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WTokenLogonPage extends WizardBasePanel implements IWizardPanel {
    protected JLabel mTokenNameText;
    protected JPasswordField mPasswordText, mPasswordAgainText;
    protected JTextArea mDesc;
    protected String mTokenName;
    private static final String PANELNAME = "TOKENLOGONWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-tokenlogon-help";

    WTokenLogonPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WTokenLogonPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (!wizardInfo.isNewKey() || wizardInfo.isLoggedIn())
            return false;

        mDesc.setText(mResource.getString(mPanelName+"_TEXT_HEADING_LABEL"));
        mTokenNameText.setText(wizardInfo.getTokenName());

        return true;
    }

    @Override
    public boolean validatePanel() {
        String passwd = mPasswordText.getText();
        if (passwd.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }

        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        String tokenname = mTokenNameText.getText().trim();

        if (tokenname.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
            tokenname = CryptoUtil.INTERNAL_TOKEN_NAME;
        }

        String pwd = mPasswordText.getText().trim();
        startProgressStatus();

        try {
            NameValuePairs nvps = new NameValuePairs();
            nvps.put(Constants.PR_TOKEN_NAME, tokenname);
            nvps.put(Constants.PR_TOKEN_PASSWD, pwd);
            connection.modify(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_TOKEN_LOGON, Constants.RS_ID_CONFIG, nvps);
        } catch (EAdminException e) {
            setErrorMessage(e.toString());
            endProgressStatus();
            return false;
        }

        endProgressStatus();

        return true;
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
        mDesc = createTextArea("");
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
        mTokenNameText = new JLabel(" ");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mTokenNameText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel passwordLabel = makeJLabel("PWD");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(passwordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordText, gbc);

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
}

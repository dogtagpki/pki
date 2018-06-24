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
import java.util.StringTokenizer;

import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;

/**
 * Token Selection page for certificate setup wizard
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WTokenSelectionPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mInstallBtn;
    private JRadioButton mRequestBtn;
    private JComboBox<String> mToken;
    private static final String PANELNAME = "TOKENSELECTIONWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WTokenSelectionPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String tokenList = (String)wizardInfo.getEntry(Constants.PR_TOKEN_LIST);
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ",");
        while (tokenizer.hasMoreTokens()) {
            mToken.addItem(tokenizer.nextToken());
        }
        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        info.addEntry(CertSetupWizardInfo.TOKENNAME, mToken.getSelectedItem());
        if (mRequestBtn.isSelected())
            info.addEntry(CertSetupWizardInfo.OPTYPE, CertSetupWizardInfo.REQUESTTYPE);
        else
            info.addEntry(CertSetupWizardInfo.OPTYPE, CertSetupWizardInfo.INSTALLTYPE);
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel operationTypeLbl = makeJLabel("OPERATIONTYPE");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(operationTypeLbl, gbc);

        ButtonGroup btnGroup = new ButtonGroup();
        CMSAdminUtil.resetGBC(gbc);
        mInstallBtn = makeJRadioButton("INSTALL", true);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,4*COMPONENT_SPACE,
          COMPONENT_SPACE, 0);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mInstallBtn, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRequestBtn = makeJRadioButton("REQUEST", false);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, 2*COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mRequestBtn, gbc);

        btnGroup.add(mInstallBtn);
        btnGroup.add(mRequestBtn);

        CMSAdminUtil.resetGBC(gbc);
        JLabel tokenTypeLbl = makeJLabel("TOKENSELECTION");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(tokenTypeLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel tokenLbl = makeJLabel("TOKEN");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,4*COMPONENT_SPACE, COMPONENT_SPACE,0);
        add(tokenLbl, gbc);

        mToken = new JComboBox<>();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mToken, gbc);

        JTextArea dummy2 = createTextArea(" ", 1, 20);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(dummy2, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

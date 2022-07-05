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

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;

/**
 * Certificate Request from certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated
class WOtherCertRequest1Page extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mExistingKeyBtn;
    private JRadioButton mNewKeyBtn;
    private JRadioButton mEmailBtn;
    private JRadioButton mURLBtn;
    private JRadioButton mManualBtn;
    private static final String PANELNAME = "CACERTREQUESTWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WOtherCertRequest1Page() {
        super(PANELNAME);
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.INSTALLTYPE))
            return false;

        String type = wizardInfo.getCertType();
        if (type.equals(Constants.PR_CA_SIGNING_CERT))
            return false;

        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (mNewKeyBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.KEY_MATERIAL, Constants.TRUE);
        else if (mExistingKeyBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.KEY_MATERIAL, Constants.FALSE);

        if (mEmailBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.SUBMIT_METHOD, CertSetupWizardInfo.CA_EMAIL);
        else if (mURLBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.SUBMIT_METHOD, CertSetupWizardInfo.CA_URL);
        else if (mManualBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.SUBMIT_METHOD, CertSetupWizardInfo.MANUAL);

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

        JTextArea methodText = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERTREQUESTWIZARD_TEXT_METHOD_LABEL"), 80), 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(methodText, gbc);

        mEmailBtn = makeJRadioButton("EMAIL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mEmailBtn, gbc);

        mURLBtn = makeJRadioButton("URL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mURLBtn, gbc);

        mManualBtn = makeJRadioButton("MANUAL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mManualBtn, gbc);

        JLabel keyLbl = makeJLabel("KEYPAIR");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(keyLbl, gbc);

        mExistingKeyBtn = makeJRadioButton("OLDKEY", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mExistingKeyBtn, gbc);

        mNewKeyBtn = makeJRadioButton("NEWKEY", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(mNewKeyBtn, gbc);

        ButtonGroup methodGroup = new ButtonGroup();
        methodGroup.add(mURLBtn);
        methodGroup.add(mManualBtn);
        methodGroup.add(mEmailBtn);

        ButtonGroup keyGroup = new ButtonGroup();
        keyGroup.add(mExistingKeyBtn);
        keyGroup.add(mNewKeyBtn);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

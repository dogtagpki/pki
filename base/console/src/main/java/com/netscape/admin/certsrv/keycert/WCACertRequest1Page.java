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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Certificate Request from certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WCACertRequest1Page extends WizardBasePanel implements IWizardPanel {
    private JTextArea mMethodText;
    private JRadioButton mCABtn;
    private JRadioButton mSubBtn;
    private JRadioButton mExistingKeyBtn;
    private JRadioButton mNewKeyBtn;
    private JRadioButton mEmailBtn;
    private JRadioButton mURLBtn;
    private JRadioButton mManualBtn;
    private Color mActiveColor;
    private static final String PANELNAME = "CACERTREQUESTWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WCACertRequest1Page() {
        super(PANELNAME);
        init();
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.INSTALLTYPE))
            return false;

        if (wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT))
            return true;

        return false;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JLabel caLbl = makeJLabel("CATYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(caLbl, gbc);

        mCABtn = makeJRadioButton("SELFSIGN", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mCABtn, gbc);

        mSubBtn = makeJRadioButton("SUBORDINATE", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSubBtn, gbc);

        ButtonGroup caGroup = new ButtonGroup();
        caGroup.add(mCABtn);
        caGroup.add(mSubBtn);

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

        mNewKeyBtn = makeJRadioButton("NEWKEY", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mNewKeyBtn, gbc);

        ButtonGroup keyGroup = new ButtonGroup();
        keyGroup.add(mExistingKeyBtn);
        keyGroup.add(mNewKeyBtn);

        mMethodText = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERTREQUESTWIZARD_TEXT_METHOD_LABEL"), 100), 1, 100);
        mActiveColor = mMethodText.getBackground();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mMethodText, gbc);

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
        gbc.weighty = 1.0;
        add(mManualBtn, gbc);

        ButtonGroup methodGroup = new ButtonGroup();
        methodGroup.add(mEmailBtn);
        methodGroup.add(mURLBtn);
        methodGroup.add(mManualBtn);

        enableFields(false, getBackground());
        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (mCABtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.CA_TYPE, CertSetupWizardInfo.SELF_SIGNED);
        else if (mSubBtn.isSelected())
            wizardInfo.addEntry(CertSetupWizardInfo.CA_TYPE, CertSetupWizardInfo.SUBORDINATE_CA);

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
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mCABtn))
            if (mCABtn.isSelected())
                enableFields(false, getBackground());
            else
                enableFields(true, mActiveColor);
        else if (e.getSource().equals(mSubBtn))
            if (mSubBtn.isSelected())
                enableFields(true, mActiveColor);
            else
                enableFields(false, getBackground());
    }

    private void enableFields(boolean enable, Color color) {
        mMethodText.setEnabled(enable);
        mEmailBtn.setEnabled(enable);
        mURLBtn.setEnabled(enable);
        mManualBtn.setEnabled(enable);
    }
}

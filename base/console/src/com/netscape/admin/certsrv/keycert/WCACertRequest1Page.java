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
import com.netscape.admin.certsrv.connection.*;
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

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE))
            return false;

        if (wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT))
            return true;

        return false;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    public boolean isLastPage() {
        return false;
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JLabel caLbl = makeJLabel("CATYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(caLbl, gbc);

        mCABtn = makeJRadioButton("SELFSIGN", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCABtn, gbc);

        mSubBtn = makeJRadioButton("SUBORDINATE", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSubBtn, gbc);

        ButtonGroup caGroup = new ButtonGroup();
        caGroup.add(mCABtn);
        caGroup.add(mSubBtn);

        JLabel keyLbl = makeJLabel("KEYPAIR");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(keyLbl, gbc);

        mExistingKeyBtn = makeJRadioButton("OLDKEY", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mExistingKeyBtn, gbc);

        mNewKeyBtn = makeJRadioButton("NEWKEY", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNewKeyBtn, gbc);

        ButtonGroup keyGroup = new ButtonGroup();
        keyGroup.add(mExistingKeyBtn);
        keyGroup.add(mNewKeyBtn);

        mMethodText = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERTREQUESTWIZARD_TEXT_METHOD_LABEL"), 100), 1, 100);
        mActiveColor = mMethodText.getBackground();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mMethodText, gbc);

        mEmailBtn = makeJRadioButton("EMAIL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mEmailBtn, gbc);

        mURLBtn = makeJRadioButton("URL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mURLBtn, gbc);

        mManualBtn = makeJRadioButton("MANUAL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(mManualBtn, gbc);

        ButtonGroup methodGroup = new ButtonGroup();
        methodGroup.add(mEmailBtn);
        methodGroup.add(mURLBtn);
        methodGroup.add(mManualBtn);

        enableFields(false, getBackground());
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (mCABtn.isSelected())
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SELF_SIGNED);
        else if (mSubBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);

        if (mNewKeyBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.KEY_MATERIAL, Constants.TRUE);
        else if (mExistingKeyBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.KEY_MATERIAL, Constants.FALSE);

        if (mEmailBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.SUBMIT_METHOD, wizardInfo.CA_EMAIL);
        else if (mURLBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.SUBMIT_METHOD, wizardInfo.CA_URL);
        else if (mManualBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.SUBMIT_METHOD, wizardInfo.MANUAL);
    }

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

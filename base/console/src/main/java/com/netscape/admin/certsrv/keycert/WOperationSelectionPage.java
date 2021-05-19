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
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;

/**
 * Operation Selection page for certificate setup wizard
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WOperationSelectionPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mInstallBtn;
    private JRadioButton mRequestBtn;
    private static final String PANELNAME = "OPERATIONSELECTIONWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-operationselection-help";

    WOperationSelectionPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WOperationSelectionPage(JDialog parent, JFrame frame) {
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
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String mode = wizardInfo.getMode();
        // Fixes Bugscape Bug #55862:  console - Certificate Setup Wizard
        //                             throws Null Pointer Exception
        if (mode != null && mode.equals("0")) {
            info.addEntry(CertSetupWizardInfo.OPTYPE, CertSetupWizardInfo.INSTALLTYPE);
            return false;
        }
        setBorder(makeTitledBorder(PANELNAME));
        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        startProgressStatus();
        if (mRequestBtn.isSelected())
            info.addEntry(CertSetupWizardInfo.OPTYPE, CertSetupWizardInfo.REQUESTTYPE);
        else
            info.addEntry(CertSetupWizardInfo.OPTYPE, CertSetupWizardInfo.INSTALLTYPE);
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
        JTextArea operationTypeLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_OPERATIONTYPE_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(operationTypeLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRequestBtn = makeJRadioButton("REQUEST", true);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mRequestBtn, gbc);

        ButtonGroup btnGroup = new ButtonGroup();
        CMSAdminUtil.resetGBC(gbc);
        mInstallBtn = makeJRadioButton("INSTALL", false);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,COMPONENT_SPACE, 0);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mInstallBtn, gbc);

        btnGroup.add(mInstallBtn);
        btnGroup.add(mRequestBtn);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

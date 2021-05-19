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
 * Introduction page for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WWarningExecutePage extends WizardBasePanel implements IWizardPanel {
    private JButton mAgree;
    private boolean mIsAgree = false;
    private static final String PANELNAME = "WARNINGEXECUTEWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WWarningExecutePage() {
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
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.REQUESTTYPE) &&
          wizardInfo.isNewKey() &&
          wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT) &&
          wizardInfo.getCAType().equals(CertSetupWizardInfo.SELF_SIGNED))
        return true;

        return false;
    }

    @Override
    public boolean validatePanel() {
        if (mIsAgree)
            return true;
        else {
            setErrorMessage("PROCEED");
            return false;
        }
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = wizardInfo.getNameValuePairs();
        try {
            connection.modify(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_ISSUE_IMPORT_CERT,
              wizardInfo.getCertType(), nvps);
        } catch (EAdminException e) {
            setErrorMessage(e.toString());
            return false;
        }
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

        Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON);

        JLabel label = new JLabel(icon);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(label, gbc);

        JTextArea desc = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGEXECUTEWIZARD_TEXT_DESC_LABEL"), 80), 3, 80);

        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        JTextArea desc1 = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGEXECUTEWIZARD_LABEL_WARNING_LABEL"), 60), 3, 60);
        desc1.setBackground(getBackground());
        desc1.setEditable(false);
        desc1.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(desc1, gbc);

        mAgree = makeJButton("OK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mAgree, gbc);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mAgree)) {
            mIsAgree = true;
        }
    }
}

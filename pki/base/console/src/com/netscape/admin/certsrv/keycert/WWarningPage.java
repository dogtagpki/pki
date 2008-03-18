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
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.keycert
 */
class WWarningPage extends WizardBasePanel implements IWizardPanel {
    private JButton mAgree;
    private boolean mIsAgree = false;
    private static final String PANELNAME = "WARNINGWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";
    
    WWarningPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE) &&
          wizardInfo.isNewKey() && 
          wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT))
        return true;
            
        return false; 
    }

    public boolean validatePanel() {
        if (mIsAgree)
            return true;
        else {
            setErrorMessage("PROCEED");
            return false;
        }
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON);

        JLabel label = new JLabel(icon);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(label, gbc);

        JTextArea desc = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGWIZARD_TEXT_DESC_LABEL"), 80), 3, 80);

        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        JTextArea desc1 = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGWIZARD_LABEL_WARNING_LABEL"), 80), 1, 80);
        desc1.setBackground(getBackground());
        desc1.setEditable(false);
        desc1.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(desc1, gbc);

        mAgree = makeJButton("OK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mAgree, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mAgree)) {
            mIsAgree = true;
        }
    }
}

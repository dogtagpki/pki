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
class WIssueImportStatusPage extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "ISSUEIMPORTSTATUSWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-selfsignedstatus-help";
    private JTextArea desc;
    
    WIssueImportStatusPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIssueImportStatusPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String str = "";

        if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE) &&
            (wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED) ||
			wizardInfo.isSSLCertLocalCA())) {
            str = mResource.getString(
              "ISSUEIMPORTSTATUSWIZARD_TEXT_DESC_LABEL");
            desc.setText(str);
            return true; 
        } 
        return false;
    }

    public boolean isLastPage() {
        return true;
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

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

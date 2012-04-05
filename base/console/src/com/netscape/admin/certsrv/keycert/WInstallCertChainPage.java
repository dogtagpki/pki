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
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * This page allows the user to do such selections as the installation of
 * certificates, server certificate chain, or trusted CA.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WInstallCertChainPage extends WizardBasePanel implements IWizardPanel {
    private JComboBox mCertBox;
    private String mTrustedCACert;
    private String mTrustedCert, mOtherCert, mCrossCert;
    private static final String PANELNAME = "INSTALLCERTCHAINWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-installcerttype-help";

    WInstallCertChainPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WInstallCertChainPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE))
            return false;

        setBorder(makeTitledBorder(PANELNAME));

        String mode = wizardInfo.getMode();
        if (mode != null && mode.equals("0")) {
            return true;
        }

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

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea introLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_INTRO_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(introLbl, gbc);

        JTextArea opLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_INSTALLCERT_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(opLbl, gbc);

        mCertBox = makeJComboBox("CERTCHAINTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weighty = 1.0;
        add(mCertBox, gbc);

        JTextArea dummy = createTextArea(" ", 1, 10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,COMPONENT_SPACE);
        add(dummy, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String str = (String)(mCertBox.getSelectedItem());
        if (str.startsWith("Trusted")) {
            wizardInfo.addEntry(wizardInfo.INSTALLCERTTYPE, Constants.PR_TRUSTED_CA_CERT);
        } else if (str.startsWith("Untrusted")) {
            wizardInfo.addEntry(wizardInfo.INSTALLCERTTYPE, Constants.PR_SERVER_CERT_CHAIN);
        }
    }
}

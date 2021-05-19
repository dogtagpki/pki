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
class WExecutePage extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "EXECUTEWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-selfsignedcert-help";
    private JTextArea desc;

    WExecutePage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WExecutePage(JDialog parent, JFrame frame) {
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
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.REQUESTTYPE) &&
//          !wizardInfo.isNewKey() &&
          ((wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT) &&
          wizardInfo.getCAType().equals(CertSetupWizardInfo.SELF_SIGNED))
		  ||
		  (wizardInfo.getCertType().equals(Constants.PR_OCSP_SIGNING_CERT) &&
		   wizardInfo.isSSLCertLocalCA())
		  ||
		  (wizardInfo.getCertType().equals(Constants.PR_SERVER_CERT) &&
		   wizardInfo.isSSLCertLocalCA())
		  ||
		  (wizardInfo.getCertType().equals(Constants.PR_SERVER_CERT_RADM) &&
		   wizardInfo.isSSLCertLocalCA()))) {

            setBorder(makeTitledBorder(PANELNAME));

            if (wizardInfo.isNewKey()) {
                String str = mResource.getString(
                  "EXECUTEWIZARD_TEXT_NEWKEY_LABEL");
                desc.setText(str);
            } else {
                String str = mResource.getString(
                  "EXECUTEWIZARD_TEXT_OLDKEY_LABEL");
                desc.setText(str);
            }
            return true;
        }

        return false;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        startProgressStatus();
        AdminConnection connection = wizardInfo.getAdminConnection();
        CMSServerInfo serverInfo = wizardInfo.getServerInfo();

        String dir = "";
        if (wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT))
			dir = "prevCACert.txt";
		else if (wizardInfo.getCertType().equals(Constants.PR_OCSP_SIGNING_CERT))
			dir = "prevOCSPCert.txt";
		else if (wizardInfo.getCertType().equals(Constants.PR_SERVER_CERT))
			dir = "prevSSLCert.txt";
		else if (wizardInfo.getCertType().equals(Constants.PR_SERVER_CERT_RADM))
			dir = "prevSSLCertRadm.txt";

        NameValuePairs nvps = wizardInfo.getNameValuePairs();

        if (wizardInfo.isNewKey()) {
            if (wizardInfo.getHashType() != null)
                nvps.put(ConfigConstants.PR_HASH_TYPE, wizardInfo.getHashType());
            if (wizardInfo.getSignedByType() != null)
                nvps.put(ConfigConstants.PR_SIGNEDBY_TYPE, wizardInfo.getSignedByType());
        }

        nvps.put("pathname", dir);
        try {
            connection.modify(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_ISSUE_IMPORT_CERT,
              wizardInfo.getCertType(), nvps);
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

        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

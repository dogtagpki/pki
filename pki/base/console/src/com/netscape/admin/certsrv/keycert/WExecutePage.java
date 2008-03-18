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
import java.io.*;
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

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE) &&
//          !wizardInfo.isNewKey() && 
          ((wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT) &&
          wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED))
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

    public boolean validatePanel() {
        return true;
    }

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

        if (wizardInfo.isNewKey())
            nvps.add(ConfigConstants.PR_HASH_TYPE, wizardInfo.getHashType());

        nvps.add("pathname", dir);
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

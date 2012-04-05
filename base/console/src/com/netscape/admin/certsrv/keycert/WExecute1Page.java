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
import javax.swing.border.*;
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
class WExecute1Page extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "EXECUTE1WIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-certrequest-help";
    private JTextArea desc;

    WExecute1Page(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WExecute1Page(JDialog parent, JFrame frame) {
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
            wizardInfo.getCAType().equals(wizardInfo.SUBORDINATE_CA) &&
		    !(wizardInfo.isSSLCertLocalCA())) {

            String title = "";
            String certType = wizardInfo.getCertType();
            if (certType.equals(Constants.PR_CA_SIGNING_CERT))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_CASIGNING_LABEL");
            else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_OCSPSIGNING_LABEL");
            else if (certType.equals(Constants.PR_RA_SIGNING_CERT))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_RASIGNING_LABEL");
            else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_KRATRANSPORT_LABEL");
            else if (certType.equals(Constants.PR_SERVER_CERT) ||
              certType.equals(Constants.PR_SERVER_CERT_RADM))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_SERVER_LABEL");
            else if (certType.equals(Constants.PR_OTHER_CERT))
                title = mResource.getString("EXECUTE1WIZARD_BORDER_OTHER_LABEL");
            setBorder(new TitledBorder(title));

            String str = "";
            if (wizardInfo.isNewKey()) {
                str = mResource.getString("EXECUTE1WIZARD_TEXT_NEWKEY_LABEL");
            } else {
                str = mResource.getString("EXECUTE1WIZARD_TEXT_OLDKEY_LABEL");
            }
            desc.setText(str);
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
        NameValuePairs nvps = wizardInfo.getNameValuePairs();
        if (wizardInfo.getCertType().equals(Constants.PR_OTHER_CERT) &&
          !wizardInfo.isNewKey()) {
            nvps.put(Constants.PR_NICKNAME, wizardInfo.getNickname());
        }

        try {
            NameValuePairs response = connection.process(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_REQUEST,
              wizardInfo.getCertType(), nvps);
            for (String key : response.keySet()) {
                String value = response.get(key);
                if (key.equals(Constants.PR_CSR)) {
                    wizardInfo.addEntry(Constants.PR_CSR, value);
                } else if (key.equals(Constants.PR_CERT_REQUEST_DIR)) {
                    wizardInfo.addEntry(Constants.PR_CERT_REQUEST_DIR, value);
                }
            }
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

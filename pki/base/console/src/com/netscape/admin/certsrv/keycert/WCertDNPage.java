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

import javax.swing.*;
import javax.swing.border.*;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;

/**
 * CA signing cert for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WCertDNPage extends WBaseDNPage implements IWizardPanel {
    private static final String PANELNAME = "CERTDNWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-subjectdn-help";

    private String certType = "";
    
    WCertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WCertDNPage(JDialog parent, JFrame frame) {
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
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_SUBJECT_NAME, wizardInfo.getSubjectName());
        wizardInfo.addEntry(wizardInfo.ALL_INFO, nvps);

        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE) ||
          !wizardInfo.isNewKey())
            return false;

        String title = "";
        certType = wizardInfo.getCertType();
        if (certType.equals(Constants.PR_CA_SIGNING_CERT))
            title = mResource.getString("CERTDNWIZARD_BORDER_CASIGNING_LABEL");
        else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT))
            title = mResource.getString("CERTDNWIZARD_BORDER_OCSPSIGNING_LABEL");
        else if (certType.equals(Constants.PR_RA_SIGNING_CERT))
            title = mResource.getString("CERTDNWIZARD_BORDER_RASIGNING_LABEL");
        else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT))
            title = mResource.getString("CERTDNWIZARD_BORDER_KRATRANSPORT_LABEL");
        else if (certType.equals(Constants.PR_SERVER_CERT) ||
          certType.equals(Constants.PR_SERVER_CERT_RADM))
            title = mResource.getString("CERTDNWIZARD_BORDER_SERVER_LABEL");
        else if (certType.equals(Constants.PR_OTHER_CERT))
            title = mResource.getString("CERTDNWIZARD_BORDER_OTHER_LABEL");
        setBorder(new TitledBorder(title));

/*
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE) ||
          (wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED)))
            return false;
*/

        String subjectName = wizardInfo.getSubjectName();

        //mSubjectStringText.setText(subjectName)

        //dnDesc.setText(subjectName);
        //enableFields(true, mActiveColor);
        if (subjectName != null)
            populateDN(subjectName);
        return true; 
    }

    public boolean validatePanel() {
        if (certType.equals(Constants.PR_SERVER_CERT_RADM))
            return true;
        return super.validatePanel();
    }

    public boolean concludePanel(WizardInfo info) {
        startProgressStatus();
        String str1 = mSubjectDNText.getText().trim();
        String str2 = mSubjectStringText.getText().trim();
        String str = "";

        if (mDNComponents.isSelected()) {
            str = str1;
        } else {
            str = str2;
        }
        
        if (str.equals("")) {
            setErrorMessage("BLANKFIELD");
            return false;
            //str = dnDesc.getText().trim();
        }

        str = CMSAdminUtil.getPureString(str);

        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        nvps.put(Constants.PR_SUBJECT_NAME, str);
        wizardInfo.addEntry(Constants.PR_SUBJECT_NAME, str);

        try {
            connection.validate(DestDef.DEST_SERVER_ADMIN, 
              ScopeDef.SC_SUBJECT_NAME, nvps);
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            endProgressStatus();
            return false;
        }

        if (wizardInfo.isNewKey()) {
            String type = wizardInfo.getKeyType();
            if (type.equals("ECC")) {
                nvps.put(Constants.PR_KEY_CURVENAME, wizardInfo.getKeyCurveName());
            } else {
                nvps.put(Constants.PR_KEY_LENGTH, wizardInfo.getKeyLength());
            }

            nvps.put(Constants.PR_KEY_TYPE, type);
            nvps.put(Constants.PR_TOKEN_NAME, wizardInfo.getTokenName());
        }

        wizardInfo.addEntry(wizardInfo.ALL_INFO, nvps);
/*
        try {
            NameValuePairs response = connection.process(
              DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_CERT_REQUEST, wizardInfo.getCertType(), nvps);
            for (int i=0; i<response.size(); i++) {
                NameValuePair nvp = response.elementAt(i);
                String key = nvp.getName();
                String value = nvp.getValue();
                if (key.equals(Constants.PR_CSR)) {
                    wizardInfo.addEntry(Constants.PR_CSR, value);
                    break;
                }
            }
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            return false;
        }
*/

        endProgressStatus();
        wizardInfo.setSubjectName(str);
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

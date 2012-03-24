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
class WInstallOpPage extends WizardBasePanel implements IWizardPanel {
    private JComboBox mCertBox;
    private String mCASigningCert;
    private String mOCSPSigningCert;
    private String mRASigningCert;
    private String mKRATransportCert;
    private String mServerCert, mServerCertRadm;
    private String mOtherCert, mCrossCert;
    private Vector mCerts;
    private static final String PANELNAME = "INSTALLOPWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-installcerttype-help";
    
    WInstallOpPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        mCerts = new Vector();
        init();
    }

    WInstallOpPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mCerts = new Vector();
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
        String mode = wizardInfo.getMode();
        if (mode != null && mode.equals("0"))
            return false;

        setBorder(makeTitledBorder(PANELNAME));

        if (wizardInfo.getInstallCertType() != null) {
            return true;
        }

        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        try {
            NameValuePairs response = connection.search(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SUBSYSTEM, nvps);
            for (String name : response.keySet()) {
                String type = response.get(name);

                if (type.equals(Constants.PR_RA_INSTANCE))
                    mRASigningCert = mResource.getString(
                      PANELNAME+"_LABEL_RASIGNINGCERT_LABEL");
                else if (type.equals(Constants.PR_CA_INSTANCE))
                    mCASigningCert = mResource.getString(
                      PANELNAME+"_LABEL_CASIGNINGCERT_LABEL");
                else if (type.equals(Constants.PR_KRA_INSTANCE))
                    mKRATransportCert = mResource.getString(
                      PANELNAME+"_LABEL_KRATRANSPORTCERT_LABEL");
            }
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
        }

        mOCSPSigningCert = mResource.getString(
          PANELNAME+"_LABEL_OCSPSIGNINGCERT_LABEL");
        mServerCert = mResource.getString(
          PANELNAME+"_LABEL_SERVERCERT_LABEL");
        mServerCertRadm = mResource.getString(
          PANELNAME+"_LABEL_SERVERCERTRADM_LABEL");
        mCrossCert = mResource.getString(
          PANELNAME+"_LABEL_CROSSCERT_LABEL");
        mOtherCert = mResource.getString(
          PANELNAME+"_LABEL_OTHERCERT_LABEL");

        mCertBox.removeAllItems();
        mCerts.removeAllElements();

        if (mCASigningCert != null) {
            mCertBox.addItem(mCASigningCert);
            mCerts.addElement(Constants.PR_CA_SIGNING_CERT);
        }
        if (mOCSPSigningCert != null) {
            mCertBox.addItem(mOCSPSigningCert);
            mCerts.addElement(Constants.PR_OCSP_SIGNING_CERT);
        }
        if (mRASigningCert != null) {
            mCertBox.addItem(mRASigningCert);
            mCerts.addElement(Constants.PR_RA_SIGNING_CERT);
        }
        if (mKRATransportCert != null) {
            mCertBox.addItem(mKRATransportCert);
            mCerts.addElement(Constants.PR_KRA_TRANSPORT_CERT);
        }
        if (mServerCert != null) {
            mCertBox.addItem(mServerCert);
            mCerts.addElement(Constants.PR_SERVER_CERT);
        }

        if (mCrossCert != null) {
            mCertBox.addItem(mCrossCert); 
            mCerts.addElement(Constants.PR_CROSS_CERT);
        }

        if (mOtherCert != null) {
            mCertBox.addItem(mOtherCert); 
            mCerts.addElement(Constants.PR_OTHER_CERT);
        }

        // that means the wizard is launched from the task page
        if (mode == null) {
            mCertBox.addItem("Untrusted CA Certificate Chain");
            mCertBox.addItem("Trusted CA Certificate Chain");
        }

        mCertBox.setSelectedIndex(0);
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
 
        mCertBox = makeJComboBox("CERTTYPE");
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
        int index = mCertBox.getSelectedIndex();
        wizardInfo.addEntry(wizardInfo.INSTALLCERTTYPE, mCerts.elementAt(index));
    }
}

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

import java.util.*;
import java.awt.*;
import java.io.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;

/**
 * Generate cert request page for cert setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WManualCertRequestPage extends WBaseManualCertRequestPage implements IWizardPanel {

    public static final String SERVER_CERT = "server";
    public static final String CLIENT_CERT = "client";
    public static final String CA_CERT = "ca";
    public static final String RA_CERT = "ra";
    public static final String OCSP_CERT = "ocsp";
    public static final String OBJECT_SIGNING_CERT = "objSignClient";
    public static final String OTHER_CERT = "other";
    public static final String ROUTER_CERT = "router"; // deprecated
    public static final String CEP_CERT = "CEP-Request";

    private static final String PANELNAME = "MANUALCERTREQUESTWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-displaycertrequest-help";
    
    WManualCertRequestPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WManualCertRequestPage(JDialog parent, JFrame frame) {
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
     
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE) ||
          wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED))
            return false;

        String str = wizardInfo.getCSR();
//        mText.setText(CMSAdminUtil.certRequestWrapText(str, 40));
        mText.setText(str);
        mText.selectAll();
        setBorder(makeTitledBorder(PANELNAME));

        CMSServerInfo serverInfo = wizardInfo.getServerInfo();
        String certType = wizardInfo.getCertType();
        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_CADESC_LABEL"));
            str = mResource.getString(mPanelName+"_TEXT_CAFILELOC_LABEL");
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            str = mResource.getString(mPanelName+"_TEXT_OCSPFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_RADESC_LABEL"));
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
            str = mResource.getString(mPanelName+"_TEXT_RAFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_RADESC_LABEL"));
        } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
            str = mResource.getString(mPanelName+"_TEXT_KRAFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_KRADESC_LABEL"));
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            str = mResource.getString(mPanelName+"_TEXT_SSLFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_SSLDESC_LABEL"));
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            str = mResource.getString(mPanelName+"_TEXT_SSLRADMFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_SSLDESC_LABEL"));
        } else if (certType.equals(Constants.PR_OTHER_CERT)) {
            str = mResource.getString(mPanelName+"_TEXT_OTHERFILELOC_LABEL");
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_OTHERDESC_LABEL"));
        }

        String dir = wizardInfo.getCertRequestDir();
        mFileName.setText(str+dir+".");

        if (mSendNowBox.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());
		String host = wizardInfo.getCMHost();
		if (host != null && !host.equals(""))
			mHostText.setText(host);
		String port = wizardInfo.getCMEEPort();
		if (port != null && !port.equals(""))
			mPortText.setText(port);

        return true; 
    }

    public boolean validatePanel() {
        return super.validatePanel();
    }

    public boolean concludePanel(WizardInfo info) {
		if (!mSendNowBox.isSelected())
			return true;

        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
		if (mHost != null && !mHost.equals(""))
			wizardInfo.setCMHost(mHost);
		if (mPort != null && !mPort.equals(""))
			wizardInfo.setCMEEPort(mPort);   
		if (mSSL.isSelected())
			wizardInfo.setCMEEType("https");
		else
			wizardInfo.setCMEEType("http");

        CMSCertRequest requestCertCgi = new CMSCertRequest();
        requestCertCgi.initialize(wizardInfo);
        Hashtable data = new Hashtable();

        String certType = null;

        String mReqType = wizardInfo.getCertType();
        String mReq = null;

        mReq = wizardInfo.getCSR();

        if (mReqType.equals(Constants.PR_CA_SIGNING_CERT)){
                        data.put("profileId", "caCACert");
        }else if (mReqType.equals(Constants.PR_SERVER_CERT) ||
                  mReqType.equals(Constants.PR_KRA_TRANSPORT_CERT)){
                        data.put("profileId", "caServerCert");
        }else if (mReqType.equals(Constants.PR_OCSP_SIGNING_CERT)){
                        data.put("profileId", "caOCSPCert");
        }else if (mReqType.equals(Constants.PR_RA_SIGNING_CERT)){
                        data.put("profileId", "caRACert");
        }else if (mReqType.equals(Constants.PR_OTHER_CERT)) {
            data.put("profileId", "caOtherCert");
        } else {
                        data.put("profileId", mReqType);
        }

            data.put("cert_request_type", "pkcs10");
            data.put("cert_request", mReq);

        startProgressStatus();
        boolean ready = requestCertCgi.requestCert(data);
        endProgressStatus();

        if (!ready) {
            String str = requestCertCgi.getErrorMessage();
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

		wizardInfo.setRequestSent(ready);
        return ready;
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

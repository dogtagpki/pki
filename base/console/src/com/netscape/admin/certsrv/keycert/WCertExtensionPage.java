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

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.border.TitledBorder;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.config.WBaseCertExtensionPage;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * Certificate Extension for setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WCertExtensionPage extends WBaseCertExtensionPage implements
  IWizardPanel {
    private static final String PANELNAME = "CERTEXTENSION1WIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-extension-help";

    WCertExtensionPage(JDialog parent) {
        super(PANELNAME);
        mPanelName = PANELNAME;
        mParent = parent;
        init();
    }

    WCertExtensionPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mPanelName = PANELNAME;
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
		//System.out.println("extension");
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.INSTALLTYPE))
            return false;

        if (wizardInfo.getCAType().equals(CertSetupWizardInfo.SUBORDINATE_CA)
			&& !(wizardInfo.isSSLCertLocalCA()))
			return false;

        String title = "";

        if (!mModified) {
            String certType = wizardInfo.getCertType();
            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_CASIGNING_LABEL");
                mBasicCheckBox.setSelected(true);
                mAKICheckBox.setSelected(true);
                mCACheckBox.setSelected(true);
                mSKICheckBox.setSelected(true);
                mCertPathBox.setSelected(false);
                mExtendedKeyCheckBox.setSelected(false);
                mExtendedKeyCheckBox.setEnabled(true);
                mKeyUsageBox.setSelected(true);
                mOCSPNoCheck.setSelected(false);
                mOCSPNoCheck.setEnabled(true);
                mAIACheckBox.setSelected(true);
            } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_OCSPSIGNING_LABEL");
                mKeyUsageBox.setSelected(true);
                mSKICheckBox.setSelected(false);
                mSKICheckBox.setEnabled(true);
                mBasicCheckBox.setEnabled(false);
                mAKICheckBox.setSelected(true);
                mAKICheckBox.setEnabled(true);
                mCACheckBox.setSelected(false);
                mCACheckBox.setEnabled(false);
                mCertPathBox.setEnabled(false);
                mExtendedKeyCheckBox.setSelected(true);
                mOCSPSigning.setSelected(true);
                mOCSPNoCheck.setSelected(false);
                mOCSPNoCheck.setEnabled(true);
                mAIACheckBox.setSelected(true);
            } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_RASIGNING_LABEL");
                mAKICheckBox.setSelected(true);
                mExtendedKeyCheckBox.setSelected(true);
                mSSLClient.setSelected(true);
            } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_KRATRANSPORT_LABEL");
                mAKICheckBox.setSelected(true);
            } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_SERVER_LABEL");
                mExtendedKeyCheckBox.setSelected(true);
                mSSLServer.setSelected(true);
                mAKICheckBox.setSelected(true);
                mSKICheckBox.setSelected(false);
                mSKICheckBox.setEnabled(true);
                mOCSPNoCheck.setSelected(false);
                mOCSPNoCheck.setEnabled(true);
                mAIACheckBox.setSelected(true);
            } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                title = mResource.getString(
                  "CERTEXTENSION1WIZARD_BORDER_SERVER_LABEL");
                mExtendedKeyCheckBox.setSelected(true);
                mAKICheckBox.setSelected(true);
                mSSLServer.setSelected(true);
            }
        }

        setBorder(new TitledBorder(title));

        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

        if (mMIMECheckBox.isSelected()) {
            startProgressStatus();
            NameValuePairs nvps = new NameValuePairs();
            nvps.put(ConfigConstants.PR_CERTIFICATE_EXTENSION, mMIMEText.getText().trim());
            AdminConnection connection = wizardInfo.getAdminConnection();
            try {
                connection.validate(
                  DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERTIFICATE_EXTENSION, nvps);
            } catch (EAdminException e) {
                setErrorMessage(e.toString());
                return false;
            }
            endProgressStatus();
        }

        NameValuePairs nvps = new NameValuePairs();

        nvps.put(Constants.PR_SUBJECT_NAME, wizardInfo.getSubjectName());
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
        //nvps.add(Constants.PR_VALIDITY_PERIOD, wizardInfo.getValidityPeriod());
        addValidityPeriod(wizardInfo, nvps);

        if (mBasicCheckBox.isSelected())
            addBasicConstraints(nvps);

        if (mExtendedKeyCheckBox.isSelected())
            addExtendedKey(nvps);

        if (mAIACheckBox.isSelected())
            nvps.put(Constants.PR_AIA, Constants.TRUE);

        if (mAKICheckBox.isSelected())
            nvps.put(Constants.PR_AKI, Constants.TRUE);

        if (mSKICheckBox.isSelected())
            nvps.put(Constants.PR_SKI, Constants.TRUE);

        if (mOCSPNoCheck.isSelected())
            nvps.put(Constants.PR_OCSP_NOCHECK, Constants.TRUE);

        if (mKeyUsageBox.isSelected())
            nvps.put(Constants.PR_KEY_USAGE, Constants.TRUE);

        if (mMIMECheckBox.isSelected())
            nvps.put(Constants.PR_DER_EXTENSION, mMIMEText.getText().trim());

        wizardInfo.addEntry(CertSetupWizardInfo.ALL_INFO, nvps);

        mModified = true;
        return true;
    }

    private void addValidityPeriod(CertSetupWizardInfo wizardInfo,
      NameValuePairs nvps) {
        nvps.put(Constants.PR_BEGIN_YEAR, wizardInfo.getBeginYear());
        nvps.put(Constants.PR_BEGIN_MONTH, wizardInfo.getBeginMonth());
        nvps.put(Constants.PR_BEGIN_DATE, wizardInfo.getBeginDate());
        nvps.put(Constants.PR_BEGIN_HOUR, wizardInfo.getBeginHour());
        nvps.put(Constants.PR_BEGIN_MIN, wizardInfo.getBeginMin());
        nvps.put(Constants.PR_BEGIN_SEC, wizardInfo.getBeginSec());
        nvps.put(Constants.PR_AFTER_YEAR, wizardInfo.getAfterYear());
        nvps.put(Constants.PR_AFTER_MONTH, wizardInfo.getAfterMonth());
        nvps.put(Constants.PR_AFTER_DATE, wizardInfo.getAfterDate());
        nvps.put(Constants.PR_AFTER_HOUR, wizardInfo.getAfterHour());
        nvps.put(Constants.PR_AFTER_MIN, wizardInfo.getAfterMin());
        nvps.put(Constants.PR_AFTER_SEC, wizardInfo.getAfterSec());
    }

    private void addBasicConstraints(NameValuePairs nvps) {

        if (mCACheckBox.isSelected())
            nvps.put(Constants.PR_IS_CA, Constants.TRUE);

        String certLen = mCertPathText.getText().trim();
        if (!certLen.equals(""))
            nvps.put(Constants.PR_CERT_LEN, certLen);
    }

    private void addExtendedKey(NameValuePairs nvps) {

        if (mSSLClient.isSelected())
            nvps.put(Constants.PR_SSL_CLIENT_BIT, Constants.TRUE);
        if (mSSLServer.isSelected())
            nvps.put(Constants.PR_SSL_SERVER_BIT, Constants.TRUE);
        if (mSSLMail.isSelected())
            nvps.put(Constants.PR_SSL_MAIL_BIT, Constants.TRUE);
        if (mObjectSigning.isSelected())
            nvps.put(Constants.PR_OBJECT_SIGNING_BIT, Constants.TRUE);
        if (mTimeStamping.isSelected())
            nvps.put(Constants.PR_TIMESTAMPING_BIT, Constants.TRUE);
        if (mOCSPSigning.isSelected())
            nvps.put(Constants.PR_OCSP_SIGNING, Constants.TRUE);
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

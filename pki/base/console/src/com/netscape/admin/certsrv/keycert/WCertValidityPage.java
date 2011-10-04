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
import javax.swing.border.*;
import javax.swing.event.*;
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
class WCertValidityPage extends WBaseValidityPage implements IWizardPanel {
    private static final String PANELNAME = "CERTVALIDWIZARD";
    private String mCertType = "";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-validityperiod-help";
    
    WCertValidityPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WCertValidityPage(JDialog parent, JFrame frame) {
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
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE) )
            return false;
		if ((wizardInfo.getCAType().equals(wizardInfo.SUBORDINATE_CA))
			&& !(wizardInfo.isSSLCertLocalCA()))
			return false;

        String title = "";
        mCertType = wizardInfo.getCertType();
        if (mCertType.equals(Constants.PR_CA_SIGNING_CERT))
            title = mResource.getString("CERTVALIDWIZARD_BORDER_CASIGNING_LABEL");
        else if (mCertType.equals(Constants.PR_OCSP_SIGNING_CERT))
            title = mResource.getString("CERTVALIDWIZARD_BORDER_OCSPSIGNING_LABEL");
        else if (mCertType.equals(Constants.PR_RA_SIGNING_CERT))
            title = mResource.getString("CERTVALIDWIZARD_BORDER_RASIGNING_LABEL");
        else if (mCertType.equals(Constants.PR_KRA_TRANSPORT_CERT))
            title = mResource.getString("CERTVALIDWIZARD_BORDER_KRATRANSPORT_LABEL");
        else if (mCertType.equals(Constants.PR_SERVER_CERT) ||
          mCertType.equals(Constants.PR_SERVER_CERT_RADM))
            title = mResource.getString("CERTVALIDWIZARD_BORDER_SERVER_LABEL");
        setBorder(new TitledBorder(title));

        return true; 
    }

    public boolean validatePanel() {
        boolean status = super.validatePanel();
        if (status && !mWarningDisplayed) {
            Date currTime = new Date();
            if (currTime.before(mBeforeDate)) {
                if (mCertType.equals(Constants.PR_CA_SIGNING_CERT))
                    setErrorMessage("INVALIDCACERT");
                else if (mCertType.equals(Constants.PR_OCSP_SIGNING_CERT))
                    setErrorMessage("INVALIDOCSPCERT");
                else if (mCertType.equals(Constants.PR_RA_SIGNING_CERT))
                    setErrorMessage("INVALIDRACERT");
                else if (mCertType.equals(Constants.PR_KRA_TRANSPORT_CERT))
                    setErrorMessage("INVALIDKRACERT");
                else if (mCertType.equals(Constants.PR_SERVER_CERT))
                    setErrorMessage("INVALIDSSLCERT");
                mWarningDisplayed = true;
                return false;
            }
        }
        return status;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    protected void init() {
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        wizardInfo.addEntry(Constants.PR_BEGIN_YEAR, mBYear.getText().trim());
        int beforeMonth = Integer.parseInt(mBMonth.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_MONTH, ""+(beforeMonth-1));
        wizardInfo.addEntry(Constants.PR_BEGIN_DATE, mBDay.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_HOUR, mBHour.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_MIN, mBMin.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_SEC, mBSec.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_YEAR, mEYear.getText().trim());
        int afterMonth = Integer.parseInt(mEMonth.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_MONTH, ""+(afterMonth-1));
        wizardInfo.addEntry(Constants.PR_AFTER_DATE, mEDay.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_HOUR, mEHour.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_MIN, mEMin.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_SEC, mESec.getText().trim());
        //wizardInfo.addEntry(Constants.PR_VALIDITY_PERIOD, ""+period);
    }
}

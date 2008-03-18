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
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WCertDNValidityPage extends WBaseDNValidityPage implements IWizardPanel {
    private static final String PANELNAME = "CERTDNVALIDWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";
    
    WCertDNValidityPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE) ||
          (wizardInfo.getCAType().equals(wizardInfo.SUBORDINATE_CA)))
            return false;

        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        String str = mSubjectDNText.getText().trim();
        
        if (str.equals("")) {
            setErrorMessage("BLANKFIELD");
            return false;
        }

        str = CMSAdminUtil.getPureString(str);

        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        wizardInfo.addEntry(Constants.PR_SUBJECT_NAME, str);

        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String valid = mValidityText.getText().trim();
        int period = Integer.parseInt(valid);
        int index = mUnitBox.getSelectedIndex();

        if (index == 1) {
            period = period*30;
        } else if (index == 2) {
            period = period*365;
        }
        wizardInfo.addEntry(Constants.PR_VALIDITY_PERIOD, ""+period);
    }
}

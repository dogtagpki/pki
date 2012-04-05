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
 * Setup CA signing cert for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WCAKeyPage extends WBaseKeyPage implements IWizardPanel {
    private static final String PANELNAME = "CAKEYWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WCAKeyPage() {
        super(PANELNAME);
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE))
        //  (wizardInfo.isNewKey()))
            return false;

        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
/*
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        nvps.add(Constants.PR_TOKEN_NAME, wizardInfo.getTokenName());
        nvps.add(Constants.PR_KEY_LENGTH, (String)mKeyLengthBox.getSelectedItem());
        nvps.add(Constants.PR_KEY_TYPE, (String)mKeyTypeBox.getSelectedItem());

        try {
            NameValuePairs response = connection.process(
              DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_CA_SIGNINGCERT,
              Constants.PR_CERT_REQUEST, nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            return false;
        }
*/

        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        super.init();
    }

    public boolean isLastPage() {
        return false;
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        wizardInfo.addEntry(Constants.PR_KEY_LENGTH,
          (String)mKeyLengthBox.getSelectedItem());
        wizardInfo.addEntry(Constants.PR_KEY_TYPE,
          (String)mKeyTypeBox.getSelectedItem());
    }
}

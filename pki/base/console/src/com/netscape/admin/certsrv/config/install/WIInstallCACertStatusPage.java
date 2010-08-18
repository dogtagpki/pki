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
package com.netscape.admin.certsrv.config.install;

import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import javax.swing.*;

/**
 * The panel asks the user to paste the certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInstallCACertStatusPage extends WIInstallCertStatusPage {
    private static final String PANELNAME = "INSTALLCACERTSTATUSWIZARD";
    private static final String CAHELPINDEX = "install-cacert-status-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakracert-status-wizard-help";

    WIInstallCACertStatusPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIInstallCACertStatusPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;
        if (wizardInfo.isCACertLocalCA() || !wizardInfo.isCACertInstalledDone() ||
          !wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
          wizardInfo.isCACertChainImportDone())
            return false;

		if (wizardInfo.hasEntireCAChain())
			return false;

        wizardInfo.setCertType(Constants.PR_CA_SIGNING_CERT);

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;

        return super.initializePanel(info);
    }
}



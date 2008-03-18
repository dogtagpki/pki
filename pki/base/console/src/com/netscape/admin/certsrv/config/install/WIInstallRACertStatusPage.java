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
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInstallRACertStatusPage extends WIInstallCertStatusPage {
    private static final String PANELNAME = "INSTALLRACERTSTATUSWIZARD";
    private static final String RAHELPINDEX = "install-racert-status-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakracert-status-wizard-help";

    WIInstallRACertStatusPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIInstallRACertStatusPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        if (wizardInfo.isRACertLocalCA() || !wizardInfo.isRACertInstalledDone() ||
          !wizardInfo.isRAInstalled() || wizardInfo.isRACertChainImportDone())
            return false;

		if (wizardInfo.hasEntireRAChain()) 
			return false;

        wizardInfo.setCertType(Constants.PR_RA_SIGNING_CERT);

        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;

        return super.initializePanel(info);
    }
}



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
import javax.swing.*;
import com.netscape.certsrv.common.*;

/**
 * The panel displays the certificate which will be installed in the token.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIDisplayCACertPage extends WIDisplayCertPage {
    private static final String PANELNAME = "INSTALLDISPLAYCACERTWIZARD";
    private static final String CAHELPINDEX = "install-cacert-display-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakracert-display-wizard-help";

    WIDisplayCACertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIDisplayCACertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;

        if (wizardInfo.isCACertLocalCA() || !wizardInfo.isInstallCertNow() ||
          !wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
          wizardInfo.isCACertInstalledDone())
            return false;

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        if (super.concludePanel(info)) {
            InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
            wizardInfo.put(ConfigConstants.STAGE_CA_CERT_REQUEST,
              ConfigConstants.TRUE);
            return true;
        }

        return false;
    }
}


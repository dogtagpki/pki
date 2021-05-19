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

import javax.swing.*;
import com.netscape.admin.certsrv.wizard.*;

/**
 * Certificate Extension page for SSL server Certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIServerCertExtensionPage extends WICertExtensionPage {
    private static final String PANELNAME = "INSTALLSERVERCERTEXTENSION1WIZARD";
    private static final String HELPINDEX = "install-sslcert-extension-wizard-help";

    WIServerCertExtensionPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        mHelpIndex = HELPINDEX;
    }

    WIServerCertExtensionPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mHelpIndex = HELPINDEX;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning())
            return false;
        if (wizardInfo.isMigrationEnable() ||
          wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertRequestDone() ||
          wizardInfo.isSSLCertInstalledDone())
            return false;

        if (!mModified) {
            mExtendedKeyCheckBox.setSelected(true);
            mAKICheckBox.setSelected(true);
            mSSLServer.setSelected(true);
            mSSLClient.setSelected(true);
        }
        return super.initializePanel(info);
    }
}

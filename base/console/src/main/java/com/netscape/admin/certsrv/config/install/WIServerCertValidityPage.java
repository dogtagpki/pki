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

import javax.swing.JDialog;
import javax.swing.JFrame;

import com.netscape.admin.certsrv.wizard.WizardInfo;

/**
 * Validity page for SSL server certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIServerCertValidityPage extends WICertValidityPage {
    private static final String PANELNAME = "INSTALLSERVERCERTVALIDWIZARD";
    private static final String HELPINDEX = "install-sslcert-validity-wizard-help";

    WIServerCertValidityPage(JDialog parent) {
        super(PANELNAME);
        mHelpIndex = HELPINDEX;
        mParent = parent;
    }

    WIServerCertValidityPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mHelpIndex = HELPINDEX;
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning())
            return false;
        if (wizardInfo.isMigrationEnable() || wizardInfo.isSSLLocalCertDone() ||
          wizardInfo.isSSLCertRequestDone() || wizardInfo.isSSLCertInstalledDone())
            return false;
        if (super.initializePanel(info)) {
            if (!wizardInfo.isSSLCertLocalCA())
                return false;
            return true;
        }
        return false;
    }
}


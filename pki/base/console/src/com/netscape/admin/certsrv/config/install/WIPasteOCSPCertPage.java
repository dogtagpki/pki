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
import com.netscape.management.client.util.*;

/**
 * The panel asks the user to paste the certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIPasteOCSPCertPage extends WIPasteCertPage {

    private static final String PANELNAME = "INSTALLPASTEOCSPCERTWIZARD";
    private static final String OCSPHELPINDEX = "install-ocspcert-paste-wizard-help";

    WIPasteOCSPCertPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIPasteOCSPCertPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;
        if (wizardInfo.isOCSPCertLocalCA() || !wizardInfo.isInstallCertNow() 
          || !wizardInfo.isOCSPInstalled() || wizardInfo.isOCSPCertInstalledDone())
            return false;

        wizardInfo.setCertType(Constants.PR_OCSP_SIGNING_CERT);

        mHelpIndex = OCSPHELPINDEX;
        return super.initializePanel(info);
    }
}


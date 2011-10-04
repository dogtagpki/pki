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

import java.awt.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * OCSP Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIOCSPCertSubmitPage extends WICertSubmitPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLOCSPCERTWIZARD";
    private static final String OCSPHELPINDEX = "install-ocsptype-wizard-help";

    WIOCSPCertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
					   Constants.PR_OCSP_SIGNING_CERT);

        if (!wizardInfo.isOCSPInstalled() ||
          wizardInfo.isOCSPCertRequestDone() || wizardInfo.isOCSPCertInstalledDone()
 ||
          !wizardInfo.isCAInstalled()) {
            wizardInfo.setOCSPCertLocalCA(Constants.FALSE);
            return false;
        }
        if (wizardInfo.isOCSPLocalCertDone())
            return false;

        mHelpIndex = OCSPHELPINDEX;
        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setOCSPCertLocalCA(Constants.TRUE);
        else
            wizardInfo.setOCSPCertLocalCA(Constants.FALSE);
    }
}


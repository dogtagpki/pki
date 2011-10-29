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
 * Server Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIServerCertSubmitPage extends WICertSubmitPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLSERVERCERTWIZARD";
    private static final String CALOCALHELPINDEX = "install-cassltypelocal-wizard-help";
    private static final String CAREMOTEHELPINDEX = "install-cassltypesub-wizard-help";
    private static final String CAKRALOCALHELPINDEX = "install-cakrassltypelocal-wizard-help";
    private static final String CAKRAREMOTEHELPINDEX = "install-cakrassltypesub-wizard-help";

    WIServerCertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
          Constants.PR_SERVER_CERT);

        if (wizardInfo.isCloning())
            return false;

        if (wizardInfo.isMigrationEnable() || 
          wizardInfo.isSSLCertRequestDone() || wizardInfo.isSSLCertInstalledDone() || 
          !wizardInfo.isCAInstalled()) {
            wizardInfo.setSSLCertLocalCA(Constants.FALSE);
            return false;
        }

        if (wizardInfo.isSSLLocalCertDone())
            return false;

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled()) {
            if (wizardInfo.isSSLCertLocalCA()) {
                mHelpIndex = CAKRALOCALHELPINDEX;
            } else 
                mHelpIndex = CAKRAREMOTEHELPINDEX;
        } else if (wizardInfo.isSSLCertLocalCA()) {
            mHelpIndex = CALOCALHELPINDEX;
        } else {
            mHelpIndex = CAREMOTEHELPINDEX;
        }

        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setSSLCertLocalCA(Constants.TRUE);
        else
            wizardInfo.setSSLCertLocalCA(Constants.FALSE);
    }
}

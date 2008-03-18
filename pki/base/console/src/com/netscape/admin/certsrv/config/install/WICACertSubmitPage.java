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
 * CA Certificate Submission.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACertSubmitPage extends WICertSubmitPage implements IWizardPanel {
    private static final String PANELNAME = "INSTALLCACERTWIZARD";
    private static final String CAHELPINDEX = "install-catype-wizard-help";
    private static final String CAKRAHELPINDEX = "install-cakratype-wizard-help";

    WICACertSubmitPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WICACertSubmitPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;
        
        wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
          Constants.PR_CA_SIGNING_CERT);
        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
            wizardInfo.isSelfSignedCACertDone() || wizardInfo.isCACertRequestDone() ||
            wizardInfo.isCACertInstalledDone())
            return false;
        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else
            mHelpIndex = CAHELPINDEX;
        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mSelfButton.isSelected())
            wizardInfo.setCACertLocalCA(Constants.TRUE);
        else
            wizardInfo.setCACertLocalCA(Constants.FALSE);
    }
}

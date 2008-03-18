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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

/**
 * Generate the OCSP signing certificate request
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIGenOCSPKeyCertReqPage extends WIGenKeyCertReqPage {
    private static final String PANELNAME = "INSTALLGENOCSPCERTREQWIZARD";
    private static final String OCSPHELPINDEX = "install-ocspcert-request-wizard-help";

    WIGenOCSPKeyCertReqPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIGenOCSPKeyCertReqPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;

        if (wizardInfo.isOCSPCertLocalCA() || !wizardInfo.isOCSPInstalled() ||
          (wizardInfo.isOCSPCertRequestDone() &&
			  !wizardInfo.isOCSPCertRequestBack()) || 
          wizardInfo.isOCSPLocalCertDone() ||
          wizardInfo.isOCSPCertInstalledDone())
            return false;

		if (wizardInfo.isOCSPCertRequestBack()) {
			wizardInfo.put(ConfigConstants.STAGE_OCSP_CERT_REQUEST,
						   ConfigConstants.FALSE);
			wizardInfo.put(ConfigConstants.OCSP_CERT_REQUEST_BACK,
						   ConfigConstants.FALSE);
		}

        mHelpIndex = OCSPHELPINDEX;

        mTokenName = wizardInfo.getOCSPTokenName();
        wizardInfo.setCertType(Constants.PR_OCSP_SIGNING_CERT);
		wizardInfo.setNewRequest();
        return super.initializePanel(info);
    }
}


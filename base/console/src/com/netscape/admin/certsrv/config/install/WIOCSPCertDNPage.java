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
import com.netscape.management.client.util.*;

/**
 * Subject DN page for RA signing certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIOCSPCertDNPage extends WICertDNPage {
    private static final String PANELNAME = "INSTALLOCSPCERTDNWIZARD";
    private static final String OCSPHELPINDEX = "install-ocspcert-subjectdn-wizard-help";

    WIOCSPCertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIOCSPCertDNPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isOCSPCloningDone())
            return false;

        if (!wizardInfo.isOCSPInstalled() || wizardInfo.isOCSPLocalCertDone() ||
          wizardInfo.isOCSPCertRequestDone() || wizardInfo.isOCSPCertInstalledDone())
            return false;
        String str = wizardInfo.getOCSPSubjectName();
        if (str == null || str.equals(""))
            str = OCSP_CN+", "+OCSP_C;
        wizardInfo.setOCSPSubjectName(str);
        populateDN(str);
        mHelpIndex = OCSPHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (super.concludePanel(info)) {
            wizardInfo.setOCSPSubjectName(mStr);
            return true;
        }

        return false;
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = mOText.getText().trim();
        wizardInfo.setOCSPOComp(str);
        str = mCText.getText().trim();
        wizardInfo.setOCSPCComp(str);
    }

}


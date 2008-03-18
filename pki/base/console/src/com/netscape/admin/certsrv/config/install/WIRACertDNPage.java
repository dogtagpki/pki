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

/**
 * Subject DN page for RA signing certificate 
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIRACertDNPage extends WICertDNPage {
    private static final String PANELNAME = "INSTALLRACERTDNWIZARD";
    private static final String RAHELPINDEX = "install-racert-subjectdn-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakracert-subjectdn-wizard-help";

    WIRACertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIRACertDNPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning() && wizardInfo.isRACloningDone())
            return false;
        if (!wizardInfo.isRAInstalled() || wizardInfo.isRALocalCertDone() ||
          wizardInfo.isRACertRequestDone() || wizardInfo.isRACertInstalledDone())
            return false;
        String str = wizardInfo.getRASubjectName();
        if (str == null || str.equals(""))
            str = RA_CN+", "+RA_C;
        wizardInfo.setRASubjectName(str);
        populateDN(str);
        if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = RAHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (super.concludePanel(info)) {
            wizardInfo.setRASubjectName(mStr);
            return true;
        }

        return false;
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = mOText.getText().trim();
        wizardInfo.setRAOComp(str);
        str = mCText.getText().trim();
        wizardInfo.setRACComp(str);
    }
    
}


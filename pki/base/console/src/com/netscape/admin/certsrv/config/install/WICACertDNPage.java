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
 * Subject DN page for CA signing certificate 
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACertDNPage extends WICertDNPage {
    private static final String PANELNAME = "INSTALLCACERTDNWIZARD";
    private static final String CALOCALHELPINDEX = "install-cacertlocal-subjectdn-wizard-help";
    private static final String CAREMOTEHELPINDEX = "install-cacertsub-subjectdn-wizard-help";
    private static final String CAKRALOCALHELPINDEX = "install-cakracertlocal-subjectdn-wizard-help";
    private static final String CAKRAREMOTEHELPINDEX = "install-cakracertsub-subjectdn-wizard-help";

    WICACertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WICACertDNPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isCACloningDone())
            return false;

        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
          wizardInfo.isSelfSignedCACertDone() || wizardInfo.isCACertRequestDone() ||
          wizardInfo.isCACertInstalledDone())
            return false;
        //dnDesc.setText(CA_DN);
        String str = wizardInfo.getCASubjectName();
        if (str == null || str.equals(""))
            str = CA_CN+", "+CA_C;
        wizardInfo.setCASubjectName(str);
        populateDN(str);

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            if (wizardInfo.isCACertLocalCA())
                mHelpIndex = CAKRALOCALHELPINDEX;
            else
                mHelpIndex = CAKRAREMOTEHELPINDEX;
        else if (wizardInfo.isCACertLocalCA())
            mHelpIndex = CALOCALHELPINDEX;
        else
            mHelpIndex = CAREMOTEHELPINDEX;
        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (super.concludePanel(info)) {
            wizardInfo.setCASubjectName(mStr);
            return true;
        }

        return false;
    }

    public void getUpdateInfo(WizardInfo info) {
/*
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = mOText.getText().trim();
        wizardInfo.setCAOComp(str);
        str = mCText.getText().trim();
        wizardInfo.setCACComp(str);
*/
    }
}


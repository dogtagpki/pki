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
 * Subject DN page for KRA transport certificate 
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRACertDNPage extends WICertDNPage {
    private static final String PANELNAME = "INSTALLKRACERTDNWIZARD";
    private static final String CAKRALOCALHELPINDEX = "install-cakra-kracertlocal-subjectdn-wizard-help";
    private static final String CAKRAREMOTEHELPINDEX = "install-cakra-kracertsub-subjectdn-wizard-help";
    private static final String RAKRAHELPINDEX = "install-rakra-kracertsub-subjectdn-wizard-help";
    private static final String KRAHELPINDEX = "install-kracertsub-subjectdn-wizard-help";

    WIKRACertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIKRACertDNPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning() && wizardInfo.isKRACloningDone())
            return false;
        if (!wizardInfo.isKRAInstalled() || wizardInfo.isKRALocalCertDone() ||
          wizardInfo.isKRACertRequestDone() || wizardInfo.isKRACertInstalledDone())
            return false;
//        dnDesc.setText(KRA_DN);
        String str = wizardInfo.getKRASubjectName();
        String OComp = null;
        String CComp = null;
        if (wizardInfo.isCAInstalled()) {
            // get O component
            OComp = wizardInfo.getCAOComp();
            CComp = wizardInfo.getCACComp();
        }

        if (str == null || str.equals("")) {
            if (OComp != null && !OComp.equals("")) {
                if (CComp == null || CComp.equals(""))
                    str = KRA_CN+", O="+OComp;
                else
                    str = KRA_CN+", O="+OComp+", C="+CComp;
            } else {
                if (CComp == null || CComp.equals(""))
                    str = KRA_CN;
                else
                    str = KRA_CN+", C="+CComp;
            }
        }
        wizardInfo.setKRASubjectName(str);
        populateDN(str);

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            if (wizardInfo.isKRACertLocalCA())
                mHelpIndex = CAKRALOCALHELPINDEX;
            else
                mHelpIndex = CAKRAREMOTEHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (super.concludePanel(info)) {
            wizardInfo.setKRASubjectName(mStr);
            return true;
        }

        return false;
    }
}


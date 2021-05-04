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
 * Subject DN page for SSL server certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIServerCertDNPage extends WICertDNPage {
    private static final String PANELNAME = "INSTALLSSLCERTDNWIZARD";
    private static final String LOCALHELPINDEX = "install-sslcertlocal-subjectdn-wizard-help";
    private static final String REMOTEHELPINDEX = "install-sslcertsub-subjectdn-wizard-help";

    WIServerCertDNPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WIServerCertDNPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (wizardInfo.isCloning())
            return false;
        if (wizardInfo.isMigrationEnable() || wizardInfo.isSSLLocalCertDone() ||
          wizardInfo.isSSLCertRequestDone() || wizardInfo.isSSLCertInstalledDone())
            return false;
        String machineName = wizardInfo.getMachineName();
//        dnDesc.setText("CN="+machineName+", O=Netscape Communications, C=US");
        String str = wizardInfo.getSSLSubjectName();
/*
        if (wizardInfo.isCAInstalled()) { // It is for SSL Server cert for CA
            // get O component
            OComp = wizardInfo.getCAOComp();
            CComp = wizardInfo.getCACComp();
        }
        else if (wizardInfo.isRAInstalled()) { // It is for SSL Server cert for RA
            OComp = wizardInfo.getRAOComp();
            CComp = wizardInfo.getRACComp();
        }
*/

        String OUComp = wizardInfo.getOUComponent();
        String OComp = wizardInfo.getOComponent();
        String LComp = wizardInfo.getLComponent();
        String STComp = wizardInfo.getSTComponent();
        String CComp = wizardInfo.getCComponent();

        if (str == null || str.equals("")) {
            str = "CN="+machineName;
            if (OUComp != null && !OUComp.equals("")) {
                str = str+", OU="+OUComp;
            }
            if (OComp != null && !OComp.equals("")) {
                str = str+", O="+OComp;
            }
            if (LComp != null && !LComp.equals("")) {
                str = str+", L="+LComp;
            }
            if (STComp != null && !STComp.equals("")) {
                str = str+", ST="+STComp;
            }
            if (CComp != null && !CComp.equals("")) {
                str = str+", C="+CComp;
            } else {
                str = str+", "+SERVER_C;
            }
        }
        wizardInfo.setSSLSubjectName(str);
        populateDN(str);

        if (wizardInfo.isSSLCertLocalCA())
            mHelpIndex = LOCALHELPINDEX;
        else
            mHelpIndex = REMOTEHELPINDEX;

        return super.initializePanel(info);
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (super.concludePanel(info)) {
            wizardInfo.setSSLSubjectName(mStr);
            return true;
        }

        return false;
    }
}


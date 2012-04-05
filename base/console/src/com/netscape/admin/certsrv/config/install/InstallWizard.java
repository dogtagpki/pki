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

import java.util.*;
import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;

/**
 * Wizard for Installation wizard
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */

public class InstallWizard extends WizardWidget implements Runnable {

    public InstallWizard(JFrame parent, InstallWizardInfo info,
      IWizardDone wizDone) {
        super(parent, wizDone);
        setWizardInfo(info);
        //addPage(new WIInstallCACertStatusPage());
        addPage(new WIIntroPage(this, parent));
        addPage(new WIMasterOrClone(this, parent));
        addPage(new WIClonePage(this, parent));
        addPage(new WILogonAllTokensPage(this, parent));
        addPage(new WIInternalTokenLogonPage(this, parent));
        addPage(new WIRecreateDBPage(this, parent));
        addPage(new WIInternalDBPage(this, parent));
        addPage(new WIExistingDBPage(this, parent));
        addPage(new WICreateInternalDBPage(this, parent));
        addPage(new WIInternalDBInfoPage(this, parent));
	addPage(new WIReplAgreementPage(this, parent));
        addPage(new WIAdminPage(this, parent));
        addPage(new WIServicesPage(this, parent));
        addPage(new WIInternalDBInfoPage(this, parent));
/*
	addPage(new WIRemoteCASubsystem(this, parent));
	addPage(new WIRemoteKRASubsystem(this, parent));
*/

		// CA starting serial number
		addPage(new WICASerialNumberPage(this,parent));
		addPage(new WICAOCSPServicePage(this,parent));
/*
        addPage(new WINetworkPage(this, parent));
*/

        // CA signing certificate
        addPage(new WIInternalDBInfoPage(this, parent));
        addPage(new WICloneCAKeyCertPage(this, parent));

        addPage(new WICACertSubmitPage(this, parent));
        addPage(new WICAKeyPage(this, parent));
        addPage(new WICAMessageDigestPage(this, parent));
        addPage(new WICACertDNPage(this, parent));
	addPage(new WICACertValidityPage(this, parent));
        addPage(new WICACertExtensionPage(this, parent));
        addPage(new WIGenCAKeyCertPage(this, parent));
	addPage(new WIGenCAKeyCertReqPage(this, parent));
        addPage(new WIManualCACertRequestPage(this, parent));
        addPage(new WICARequestResultPage(this,parent));
        addPage(new WIInstallCAIntroPage(this, parent));
        addPage(new WICATokenLogonPage(this, parent));
        addPage(new WIPasteCACertPage(this, parent));
        addPage(new WIDisplayCACertPage(this, parent));
        addPage(new WIInstallCACertStatusPage(this, parent));

        // OCSP signing certificate
        addPage(new WIInternalDBInfoPage(this, parent));
        addPage(new WICloneOCSPKeyCertPage(this, parent));
        addPage(new WIOCSPCertSubmitPage(this, parent));
        addPage(new WIOCSPKeyPage(this, parent));
        addPage(new WIOCSPMessageDigestPage(this, parent));
        addPage(new WIOCSPCertDNPage(this, parent));
	addPage(new WIGenOCSPKeyCertReqPage(this, parent));
        addPage(new WIManualOCSPCertRequestPage(this, parent));
	addPage(new WIOCSPRequestResultPage(this,parent));
        addPage(new WIInstallOCSPIntroPage(this, parent));
        addPage(new WIOCSPTokenLogonPage(this, parent));
        addPage(new WIPasteOCSPCertPage(this, parent));
        addPage(new WIDisplayOCSPCertPage(this, parent));
        addPage(new WIInstallOCSPCertStatusPage(this, parent));

        // RA signing certificate
        addPage(new WIInternalDBInfoPage(this, parent));
        addPage(new WICloneRAKeyCertPage(this, parent));
        addPage(new WIRACertSubmitPage(this, parent));
        addPage(new WIRAKeyPage(this, parent));
        addPage(new WIRAMessageDigestPage(this, parent));
        addPage(new WIRACertDNPage(this, parent));
        addPage(new WIRACertValidityPage(this, parent));
        addPage(new WIRACertExtensionPage(this, parent));
        addPage(new WIGenRAKeyCertPage(this, parent));
	addPage(new WIGenRAKeyCertReqPage(this, parent));
        addPage(new WIManualRACertRequestPage(this, parent));
		addPage(new WIRARequestResultPage(this,parent));
        addPage(new WIInstallRAIntroPage(this, parent));
        addPage(new WIRATokenLogonPage(this, parent));
        addPage(new WIPasteRACertPage(this, parent));
        addPage(new WIDisplayRACertPage(this, parent));
        addPage(new WIInstallRACertStatusPage(this, parent));

        // KRA transport certificate
        addPage(new WIInternalDBInfoPage(this, parent));
        addPage(new WIKRANumberPage(this, parent));
        addPage(new WICloneKRAKeyCertPage(this, parent));
        addPage(new WIKRACertSubmitPage(this, parent));
        addPage(new WIKRAKeyPage(this, parent));
        addPage(new WIKRAMessageDigestPage(this, parent));
        addPage(new WIKRACertDNPage(this, parent));
        addPage(new WIKRACertValidityPage(this, parent));
        addPage(new WIKRACertExtensionPage(this, parent));
        addPage(new WIGenKRAKeyCertPage(this, parent));
	addPage(new WIGenKRAKeyCertReqPage(this, parent));
        addPage(new WIManualKRACertRequestPage(this, parent));
		addPage(new WIKRARequestResultPage(this,parent));
        addPage(new WIInstallKRAIntroPage(this, parent));
        addPage(new WIKRATokenLogonPage(this, parent));
        addPage(new WIInternalTokenLogonPage(this, parent));
        addPage(new WIPasteKRACertPage(this, parent));
        addPage(new WIDisplayKRACertPage(this, parent));
        addPage(new WIInstallKRACertStatusPage(this, parent));
        addPage(new WIKRAStorageKeyPage(this, parent));

       	addPage(new WIKRAScheme1Page(this, parent));
      	addPage(new WIKRAScheme2Page(this, parent));

        // SSL server certificate
        addPage(new WIInternalDBInfoPage(this, parent));
        addPage(new WICloneTKSKeyCertPage(this, parent));
        addPage(new WIKRACertSubmitPage(this, parent));
        addPage(new WIServerCertSubmitPage(this, parent));
        addPage(new WIServerKeyPage(this, parent));
        addPage(new WISSLMessageDigestPage(this, parent));
        addPage(new WIServerCertDNPage(this, parent));
        addPage(new WIServerCertValidityPage(this, parent));
        addPage(new WIServerCertExtensionPage(this, parent));
        addPage(new WIGenServerKeyCertPage(this, parent));
	addPage(new WIGenSSLKeyCertReqPage(this, parent));
        addPage(new WIManualSSLCertRequestPage(this, parent));
		addPage(new WISSLRequestResultPage(this,parent));
        addPage(new WIInstallSSLIntroPage(this, parent));
        addPage(new WISSLTokenLogonPage(this, parent));
        addPage(new WIPasteSSLCertPage(this, parent));
        addPage(new WIDisplaySSLCertPage(this, parent));
        addPage(new WIInstallSSLCertStatusPage(this, parent));

        addPage(new WIAllCertsInstalledPage(this, parent));
        addPage(new WISingleSignonPage(this, parent));
        addPage(new WICertSetupStatusPage(this, parent));

        show();
    }

    protected void callHelp() {
        if (mCurrent instanceof IWizardPanel) {
            ((IWizardPanel)mCurrent).callHelp();
        }
    }

    protected void back_cb(WizardInfo info) {
        if (mCurrent instanceof WIManualCertRequestPage) {
            ((WIManualCertRequestPage)mCurrent).back_cb(info);
        }
    }

    public void run() {
        show();
    }

    public static void main(String[] args) {
        JFrame.setDefaultLookAndFeelDecorated(true);
        JFrame frame = new JFrame();
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        frame.setCursor(cursor);
        frame.invalidate();
        frame.validate();
        frame.repaint(1);
        InstallWizardInfo wizardInfo = new InstallWizardInfo();
        InstallWizard wizard = new InstallWizard(frame, wizardInfo, null);
    }
}


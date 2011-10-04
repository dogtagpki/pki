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
package com.netscape.admin.certsrv.keycert;

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;

/**
 * Wizard for Key and Certificate management
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */

public class CertSetupWizard extends WizardWidget {

    public CertSetupWizard(CMSBaseResourceModel parent, CertSetupWizardInfo info) {
        super(parent.getFrame());
        JFrame frame = parent.getFrame();
        info.addEntry(info.FRAME, frame);
        info.addEntry(info.SERVERINFO, parent.getServerInfo());
        setWizardInfo(info);
        addPage(new WIntroPage(this, frame));
//        addPage(new WTokenSelectionPage());
        addPage(new WOperationSelectionPage(this, frame));
//        addPage(new WGenerateReqPage(this));
        addPage(new WCertTypePage(this, frame));
        //addPage(new WServerCertSubmitPage(this, frame));
//        addPage(new WCACertRequest1Page());
//        addPage(new WOtherCertRequest1Page());
//        addPage(new WCAKeyPage());
        addPage(new WKeyPage(this, frame));
        addPage(new WTokenLogonPage(this, frame));
        addPage(new WCertMessageDigestPage(this, frame));
//        addPage(new WWarningPage());
        addPage(new WCertDNPage(this, frame));
        addPage(new WCertValidityPage(this, frame));
//        addPage(new WCertDNValidityPage());
//        addPage(new WWarningExecute1Page());
        addPage(new WCertExtensionPage(this, frame));
        addPage(new WExecute1Page(this, frame));
//        addPage(new WRAKeyPage());
//        addPage(new WSSLKeyPage());
//        addPage(new WWarningExecutePage());
        addPage(new WExecutePage(this, frame));
        addPage(new WIssueImportStatusPage(this, frame));
        addPage(new WManualCertRequestPage(this, frame));
        addPage(new WRequestStatusPage(this, frame));
//        addPage(new WIntroInstallCertPage());
        addPage(new WInstallOpPage(this, frame));
        addPage(new WInstallCertChainPage(this, frame));
        addPage(new WPasteCertPage(this, frame));
        addPage(new WDisplayCertPage(this, frame));
        addPage(new WInstallStatusPage(this, frame));
        show();
    }

    protected void callHelp() {
        if (mCurrent instanceof IWizardPanel) {
            ((IWizardPanel)mCurrent).callHelp();
        }
    }
}


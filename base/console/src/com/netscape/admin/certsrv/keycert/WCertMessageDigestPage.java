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
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;

/**
 * Setup the message digest information for the installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WCertMessageDigestPage extends WMessageDigestPage {

    private static final String PANELNAME = "CERTMESSAGEDIGESTWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-messagedigest-help";

    WCertMessageDigestPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
    }

    WCertMessageDigestPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String certType = wizardInfo.getCertType();

        mCAKeyType = (String)wizardInfo.get(Constants.PR_KEY_TYPE);

        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE))
            return false;

        if ((wizardInfo.getCAType().equals(wizardInfo.SUBORDINATE_CA))
            && !(wizardInfo.isSSLCertLocalCA()))
            return false;

        if (!wizardInfo.isNewKey())
            return false;

        if (wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED) &&
            certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            enableSignedByFields(true);
        } else {
            enableSignedByFields(false);
        }

        if ((!certType.equals(Constants.PR_CA_SIGNING_CERT)) &&
            (!certType.equals(Constants.PR_OCSP_SIGNING_CERT))) {

           // (!certType.equals(Constants.PR_KRA_TRANSPORT_CERT))) {
           // non-signing cert, algorithm specified by CA
           return false;
        }

        return super.initializePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (mDSAHashTypeBox.isVisible())
            wizardInfo.setHashType((String)mDSAHashTypeBox.getSelectedItem());
        else if (mECCHashTypeBox.isVisible())
            wizardInfo.setHashType((String)mECCHashTypeBox.getSelectedItem());
        else if (mRSAHashTypeBox.isVisible())
            wizardInfo.setHashType((String)mRSAHashTypeBox.getSelectedItem());

        if (mDSASignedByTypeBox.isVisible())
            wizardInfo.setSignedByType((String)mDSASignedByTypeBox.getSelectedItem());
        else if (mECCSignedByTypeBox.isVisible())
            wizardInfo.setSignedByType((String)mECCSignedByTypeBox.getSelectedItem());
        else if (mRSASignedByTypeBox.isVisible())
            wizardInfo.setSignedByType((String)mRSASignedByTypeBox.getSelectedItem());

    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }
}

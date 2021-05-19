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

import javax.swing.JDialog;
import javax.swing.JFrame;

import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This panel asks for the information of the current internal database.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInternalTokenLogonPage extends WITokenLogonPage {

    private static final String HELPINDEX = "install-internaltoken-logon-wizard-help";
    private static final String PANELNAME = "INTERNALTOKENLOGONWIZARD";

    WIInternalTokenLogonPage(JDialog dialog) {
        super(PANELNAME);
        mHelpIndex = HELPINDEX;
        mParent = dialog;
    }

    WIInternalTokenLogonPage(JDialog dialog, JFrame adminFrame) {
        super(PANELNAME);
        mHelpIndex = HELPINDEX;
        mParent = dialog;
        mAdminFrame = adminFrame;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String pwd =
          (String)wizardInfo.get("TOKEN:"+CryptoUtil.INTERNAL_TOKEN_NAME);
        if (pwd != null)
            return false;

        mTokenName = "Internal";
        mTokenText.setText(CryptoUtil.INTERNAL_TOKEN_NAME);
        return super.initializePanel(info);
    }
}


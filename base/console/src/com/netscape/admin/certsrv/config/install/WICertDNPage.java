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
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.task.*;

/**
 * Specify Subject DN  for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICertDNPage extends WBaseDNPage {
    protected String mSubjectName;
    protected String mHelpIndex;
    protected static final String CA_CN = "CN=Certificate Manager";
    protected static final String CA_C = "C=US";
    protected static final String RA_CN = "CN=Registration Manager";
    protected static final String RA_C = "C=US";
    protected static final String OCSP_CN = "CN=Online Certificate Status Manager";
    protected static final String OCSP_C = "C=US";
    protected static final String KRA_CN = "CN=Data Recovery Manager";
    protected static final String KRA_C = "C=US";
    protected static final String SERVER_C = "C=US";
    protected String mStr;

    WICertDNPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
/*
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = wizardInfo.getSubjectName();

        populateDN(str);
*/

        return true;
    }

    public boolean validatePanel() {
        return super.validatePanel();
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str1 = mSubjectDNText.getText().trim();
        String str2 = mSubjectStringText.getText().trim();
        String str = "";

        if (mDNComponents.isSelected()) {
            str = str1;
        } else {
            str = str2;
        }

        if (str.equals("")) {
            setErrorMessage("BLANKFIELD");
            return false;
            //str = dnDesc.getText().trim();
        }

        mStr = CMSAdminUtil.getPureString(str);

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CHECK_DN;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_CERTIFICATE_TYPE+"="+ wizardInfo.getCertType();
        rawData = rawData+"&"+ConfigConstants.PR_SUBJECT_NAME+"="+mStr;

	startProgressStatus();
	boolean ready = send(rawData, wizardInfo);
	endProgressStatus();

        wizardInfo.setSubjectName(mStr);

        if (!ready) {
            String errstr = getErrorMessage();
            if (errstr.equals("")) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(errstr);
        }

/*
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        nvps.add(Constants.PR_SUBJECT_NAME, str);
        wizardInfo.addEntry(Constants.PR_SUBJECT_NAME, str);

        try {
            connection.validate(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SUBJECT_NAME, nvps);
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            return false;
        }

        nvps.add(Constants.PR_TOKEN_NAME, wizardInfo.getTokenName());
        if (wizardInfo.isNewKey()) {
            nvps.add(Constants.PR_KEY_LENGTH, wizardInfo.getKeyLength());
            nvps.add(Constants.PR_KEY_TYPE, wizardInfo.getKeyType());
        }

        wizardInfo.addEntry(wizardInfo.ALL_INFO, nvps);
*/

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        super.init();
    }
}

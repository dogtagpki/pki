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
import java.awt.event.*;
import javax.swing.border.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.task.*;
import java.util.*;

/**
 * Certificate Extension for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICertExtensionPage extends WBaseCertExtensionPage implements 
  IWizardPanel {
    protected String mHelpIndex;
    
    WICertExtensionPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        return super.initializePanel(info); 
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        boolean ready = false;

        String rawData = "";
        if (mMIMECheckBox.isSelected()) {
            //Check the extension if it is valid
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CHECK_EXTENSION;
            rawData = rawData+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            rawData = rawData+ConfigConstants.PR_CERTIFICATE_EXTENSION+"="+
              mMIMEText.getText().trim();
 
            startProgressStatus();
            ready = send(rawData, wizardInfo);
            endProgressStatus();
            if (!ready) {
                String str = getErrorMessage();
                if (str.equals("")) {
                    String errorMsg = mResource.getString(
                      mPanelName+"_ERRORMSG");
                    setErrorMessage(errorMsg);
                } else
                    setErrorMessage(str);
            }
        } else
            ready = true;

        if (ready) {
            NameValuePairs nvps = new NameValuePairs();

            nvps.add(Constants.PR_CERTIFICATE_TYPE, wizardInfo.getCertType());
            nvps.add(Constants.PR_SUBJECT_NAME, wizardInfo.getSubjectName());
            nvps.add(Constants.PR_TOKEN_NAME, wizardInfo.getTokenName());
            nvps.add(Constants.PR_KEY_LENGTH, wizardInfo.getKeyLength());
            nvps.add(Constants.PR_KEY_TYPE, wizardInfo.getKeyType());
            nvps.add(Constants.PR_KEY_CURVENAME, wizardInfo.getKeyCurveName());
            addValidityPeriod(wizardInfo, nvps);

            if (mBasicCheckBox.isSelected())
                addBasicConstraints(nvps);

            if (mExtendedKeyCheckBox.isSelected())
                addExtendedKey(nvps);

            if (mAKICheckBox.isSelected())
                nvps.add(Constants.PR_AKI, Constants.TRUE);

            if (mSKICheckBox.isSelected())
                nvps.add(Constants.PR_SKI, Constants.TRUE);

            if (mKeyUsageBox.isSelected())
                nvps.add(Constants.PR_KEY_USAGE, Constants.TRUE);

            if (mMIMECheckBox.isSelected())
                nvps.add(Constants.PR_DER_EXTENSION, mMIMEText.getText().trim());

            wizardInfo.put(wizardInfo.ALL_CERT_INFO, nvps); 
        }

        mModified = true;
        return ready;
    }

    private void addValidityPeriod(InstallWizardInfo wizardInfo, 
      NameValuePairs nvps) {
        nvps.add(Constants.PR_BEGIN_YEAR, wizardInfo.getBeginYear());
        nvps.add(Constants.PR_BEGIN_MONTH, wizardInfo.getBeginMonth());
        nvps.add(Constants.PR_BEGIN_DATE, wizardInfo.getBeginDate());
        nvps.add(Constants.PR_BEGIN_HOUR, wizardInfo.getBeginHour());
        nvps.add(Constants.PR_BEGIN_MIN, wizardInfo.getBeginMin());
        nvps.add(Constants.PR_BEGIN_SEC, wizardInfo.getBeginSec());
        nvps.add(Constants.PR_AFTER_YEAR, wizardInfo.getAfterYear());
        nvps.add(Constants.PR_AFTER_MONTH, wizardInfo.getAfterMonth());
        nvps.add(Constants.PR_AFTER_DATE, wizardInfo.getAfterDate());
        nvps.add(Constants.PR_AFTER_HOUR, wizardInfo.getAfterHour());
        nvps.add(Constants.PR_AFTER_MIN, wizardInfo.getAfterMin());
        nvps.add(Constants.PR_AFTER_SEC, wizardInfo.getAfterSec());
    }

    private void addBasicConstraints(NameValuePairs nvps) {
        if (mCACheckBox.isSelected())
            nvps.add(Constants.PR_IS_CA, Constants.TRUE);

	if (mCertPathBox.isSelected()) {
            String certLen = mCertPathText.getText().trim();
            if (!certLen.equals(""))
               nvps.add(Constants.PR_CERT_LEN, certLen);
	} else {
	    // negative number means infinity
            nvps.add(Constants.PR_CERT_LEN, "-1");
	}
    }

    private void addExtendedKey(NameValuePairs nvps) {
        if (mSSLClient.isSelected()) 
            nvps.add(Constants.PR_SSL_CLIENT_BIT, Constants.TRUE);
        if (mSSLServer.isSelected())
            nvps.add(Constants.PR_SSL_SERVER_BIT, Constants.TRUE);
        if (mSSLMail.isSelected())
            nvps.add(Constants.PR_SSL_MAIL_BIT, Constants.TRUE);
        if (mObjectSigning.isSelected())
            nvps.add(Constants.PR_OBJECT_SIGNING_BIT, Constants.TRUE);
        if (mTimeStamping.isSelected())
            nvps.add(Constants.PR_TIMESTAMPING_BIT, Constants.TRUE);
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
